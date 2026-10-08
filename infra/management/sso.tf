# Who can sign in to the new accounts. Identity Center itself (the directory, the group, the
# permission set) was set up by hand and is only looked up here, by name. What this file owns
# is the last step: giving that group that permission set in each new account

data "aws_ssoadmin_instances" "this" {}

locals {
  sso_instance_arn  = one(data.aws_ssoadmin_instances.this.arns)
  identity_store_id = one(data.aws_ssoadmin_instances.this.identity_store_ids)
}

data "aws_identitystore_group" "admins" {
  identity_store_id = local.identity_store_id

  alternate_identifier {
    unique_attribute {
      attribute_path  = "DisplayName"
      attribute_value = var.admin_group
    }
  }
}

data "aws_ssoadmin_permission_set" "admin" {
  instance_arn = local.sso_instance_arn
  name         = var.admin_permission_set
}

# An assignment is what creates the AWSReservedSSO_ role inside the target account.
# Granted to the group, never to a user, so access follows group membership
resource "aws_ssoadmin_account_assignment" "admins" {
  for_each = local.new_account_ids

  instance_arn       = local.sso_instance_arn
  permission_set_arn = data.aws_ssoadmin_permission_set.admin.arn

  principal_id   = data.aws_identitystore_group.admins.group_id
  principal_type = "GROUP"

  target_id   = each.value
  target_type = "AWS_ACCOUNT"
}
