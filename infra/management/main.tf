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

  # Where the state lives: a bucket in this same account, so the pipeline in pixiu can never
  # read or change it. The bucket name is passed at init from the local backend.hcl and stays
  # out of the repo (see backend.hcl.example)
  backend "s3" {
    key    = "management.tfstate"
    region = "ca-central-1"

    # Refuse to write state unencrypted
    encrypt = true

    # A lock object next to the state, so two applies can't run at the same time
    use_lockfile = true
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
