# The management account: the organization's own guard rails (audit trail, budget alert,
# service control policy). Applied by a person from a local machine only. CI has no role in
# this account, so the pipeline can never reach what watches it

terraform {
  required_version = ">= 1.16"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.67"
    }
  }
}

provider "aws" {
  region  = "ca-central-1"
  profile = "shanhai-mgmt"
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}
data "aws_organizations_organization" "this" {}
