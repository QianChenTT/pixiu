variable "account_ids" {
  description = "The two accounts this folder deploys into. Each provider refuses to run against any other account. Set them in terraform.tfvars, which stays out of the repo"
  type = object({
    log_archive = string
    security    = string
  })
}

variable "alert_email" {
  description = "Where detection emails go. Set it in terraform.tfvars"
  type        = string
}

variable "log_retention_days" {
  description = "How long raw log files and normalized events are kept before they expire. Matches are kept"
  type        = number
  default     = 365
}

variable "query_scan_limit_bytes" {
  description = "Athena cancels any single query that would read more than this. Athena bills by data read, so this caps what one bad query can cost"
  type        = number
  default     = 1073741824 # 1 GB, about half a cent
}
