terraform {
  required_version = ">= 1.16"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.67"
    }
  }

  # Where the state lives. The bucket name is passed at init and stays out of the repo
  # (locally from backend.hcl, see backend.hcl.example. In CI from a secret)
  backend "s3" {
    key    = "pixiu.tfstate"
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
