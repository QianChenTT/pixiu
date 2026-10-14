# The platform: the network and the k3s node the app runs on. Planned on every pull request
# and applied by CI through the deploy role after Han approves. Nothing here creates IAM: the
# node's role comes from the bootstrap folder

terraform {
  required_version = ">= 1.16"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.67"
    }
  }

  # Same bucket as the bootstrap, its own state file. The bucket name comes from backend.hcl
  # on the laptop and from a GitHub secret in CI
  backend "s3" {
    key          = "platform.tfstate"
    region       = "ca-central-1"
    encrypt      = true
    use_lockfile = true
  }
}

# No profile here: on the laptop AWS_PROFILE=pixiu picks the credentials, in CI the role
# session from GitHub's token does. A profile written in the code would break CI
provider "aws" {
  region = "ca-central-1"

  # Every resource that supports tags gets these, so the console and the bill show what
  # belongs to this folder
  default_tags {
    tags = {
      Project   = "pixiu"
      Component = "platform"
      ManagedBy = "terraform"
    }
  }
}
