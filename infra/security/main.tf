# The security accounts: where the organization's logs are kept (log archive) and where they
# are turned into detections (security). One folder for both, because each side has to name
# the other: the archive bucket must let the security account's function read it and call it,
# and the function's role must be allowed to read that bucket. Applied by a person from a
# local machine only. CI has no role in either account

terraform {
  required_version = ">= 1.16"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.67"
    }

    # Builds the zip the three functions run from
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.8"
    }
  }

  # State sits next to the management account's own state, under a different key. The bucket
  # name and the profile that can reach it come from the local backend.hcl (see
  # backend.hcl.example)
  backend "s3" {
    key    = "security.tfstate"
    region = "ca-central-1"

    # Refuse to write state unencrypted
    encrypt = true

    # A lock object next to the state, so two applies can't run at the same time
    use_lockfile = true
  }
}

# Two accounts, so two providers and no default one. Every resource below names the account
# it belongs to with "provider =". One that forgot would get the default provider, which has
# no credentials here, and fail instead of landing in the wrong account.
#
# allowed_account_ids is a second lock on the same door: the provider refuses to run if its
# profile is signed in to any account but the one named in terraform.tfvars
provider "aws" {
  alias   = "log_archive"
  region  = "ca-central-1"
  profile = "shanhai-log-archive"

  allowed_account_ids = [var.account_ids.log_archive]
}

provider "aws" {
  alias   = "security"
  region  = "ca-central-1"
  profile = "shanhai-security"

  allowed_account_ids = [var.account_ids.security]
}

data "aws_partition" "current" {
  provider = aws.security
}

data "aws_region" "current" {
  provider = aws.security
}

# A member account can read the organization's ID and which account manages it, nothing more
data "aws_organizations_organization" "this" {
  provider = aws.security
}

locals {
  # The organization trail, which lives in the management account (infra/management/trail.tf).
  # Its ARN is built by hand: this folder cannot read that account, and the name is fixed there
  trail_name = "shanhai-org-trail"
  trail_arn  = "arn:${data.aws_partition.current.partition}:cloudtrail:${data.aws_region.current.region}:${data.aws_organizations_organization.this.master_account_id}:trail/${local.trail_name}"

  repo_root = "${path.module}/../.."
}
