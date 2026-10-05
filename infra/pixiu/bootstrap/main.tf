# The bootstrap: the pipeline's own foundations (state bucket, GitHub identity provider, deploy
# role). Applied by a person from a local machine only. CI never runs this folder, so the
# pipeline cannot change what it stands on through Terraform

terraform {
  required_version = ">= 1.16"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.67"
    }
  }

  # Where the state lives. The bucket name is passed at init from the local backend.hcl
  # and stays out of the repo (see backend.hcl.example)
  backend "s3" {
    key    = "bootstrap.tfstate"
    region = "ca-central-1"

    # Refuse to write state unencrypted
    encrypt = true

    # A lock object next to the state, so two applies can't run at the same time
    use_lockfile = true
  }
}

provider "aws" {
  region  = "ca-central-1"
  profile = "pixiu"
}
