# The accounts and folders (organizational units) that hold the detection environment.
# An account is the strongest wall AWS has, so each job gets its own:
#
#   security/log-archive   keeps the organization's logs. Nothing else runs there
#   security/security      turns those logs into detections
#   sandbox/range          where attacks are run on purpose
#
# security carries the log tampering policy (scp.tf). sandbox does not, on purpose: stopping a
# trail is the first attack the range has to be able to run

locals {
  root_id = data.aws_organizations_organization.this.roots[0].id
}

resource "aws_organizations_organizational_unit" "security" {
  name      = "security"
  parent_id = local.root_id
}

resource "aws_organizations_organizational_unit" "sandbox" {
  name      = "sandbox"
  parent_id = local.root_id
}

# Creating an account through the organization is the same call the console's "Add an AWS
# account" button makes. The new account starts with no root password and no root keys (root
# access is managed centrally) and with one role, OrganizationAccountAccessRole, that admins of
# this management account can assume. Day to day access comes from Identity Center (sso.tf)
resource "aws_organizations_account" "log_archive" {
  name      = "log-archive"
  email     = var.account_emails.log_archive
  parent_id = aws_organizations_organizational_unit.security.id

  # Terraform refuses any plan that would remove the account. Closing one is a decision to
  # make by hand: it takes 90 days to finish and its email address can never be used again
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_organizations_account" "security" {
  name      = "security"
  email     = var.account_emails.security
  parent_id = aws_organizations_organizational_unit.security.id

  lifecycle {
    prevent_destroy = true
  }

  # One at a time: AWS answers account creations that overlap with a conflict error
  depends_on = [aws_organizations_account.log_archive]
}

resource "aws_organizations_account" "range" {
  name      = "range"
  email     = var.account_emails.range
  parent_id = aws_organizations_organizational_unit.sandbox.id

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [aws_organizations_account.security]
}

locals {
  new_account_ids = {
    log_archive = aws_organizations_account.log_archive.id
    security    = aws_organizations_account.security.id
    range       = aws_organizations_account.range.id
  }
}

# Needed for the local CLI profiles and for infra/security's terraform.tfvars.
# Read them with: terraform output -json account_ids
output "account_ids" {
  value     = local.new_account_ids
  sensitive = true
}
