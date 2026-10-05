# A service control policy is a ceiling set from outside an account. It applies to every
# principal in the accounts it is attached to, their root users included, and nobody inside
# those accounts can remove it. It grants nothing

data "aws_organizations_organizational_units" "top" {
  parent_id = data.aws_organizations_organization.this.roots[0].id
}

locals {
  # Found by name so no ID is written into the repo. Attached to labs only: bixie sits
  # outside it and is never touched by a lab policy
  labs_ou_id = one([
    for ou in data.aws_organizations_organizational_units.top.children : ou.id if ou.name == "labs"
  ])
}

data "aws_iam_policy_document" "deny_log_tampering" {
  # No principal in a lab account may stop, delete or narrow a CloudTrail trail
  statement {
    sid    = "DenyCloudTrailTampering"
    effect = "Deny"

    actions = [
      "cloudtrail:StopLogging",
      "cloudtrail:DeleteTrail",
      "cloudtrail:UpdateTrail",
      "cloudtrail:PutEventSelectors",
      "cloudtrail:PutInsightSelectors",
    ]

    resources = ["*"]
  }

  # An account that leaves the organization drops out of the organization trail and out of
  # every policy here: log tampering by another door. Closing the account from inside takes
  # everything in it offline
  statement {
    sid    = "DenyLeavingOrClosingTheAccount"
    effect = "Deny"

    actions = [
      "organizations:LeaveOrganization",
      "account:CloseAccount",
    ]

    resources = ["*"]
  }
}

resource "aws_organizations_policy" "deny_log_tampering" {
  name        = "deny-log-tampering"
  description = "Lab accounts cannot stop, delete or narrow CloudTrail logging, leave the organization or close themselves"
  type        = "SERVICE_CONTROL_POLICY"
  content     = data.aws_iam_policy_document.deny_log_tampering.json
}

resource "aws_organizations_policy_attachment" "labs_deny_log_tampering" {
  policy_id = aws_organizations_policy.deny_log_tampering.id
  target_id = local.labs_ou_id
}
