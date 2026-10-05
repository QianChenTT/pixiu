# Keyless deploys: a GitHub Actions run proves which workflow it is with a signed token and AWS
# swaps it for a one-hour session. No AWS keys are stored in GitHub

# Tells this account to accept tokens signed by GitHub. This trusts ALL of GitHub: every
# repository there gets tokens from the same signer. The role's trust policy below is the only
# thing that narrows it down
resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
}

data "aws_iam_policy_document" "deploy_trust" {
  statement {
    sid     = "GitHubActionsOnMainOnly"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    # The token must have been issued for AWS
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # The token must come from this repo and from a run on main, so only code that passed the
    # PR rule and the CI gates. An exact match on purpose: a wildcard here would let any
    # branch, tag or pull request in the repo take the role.
    # The numbers are GitHub's permanent IDs for the owner and the repo (the repo's "immutable
    # subject" setting, on by default here). A name can be given up and registered by someone
    # else, an ID can't. Check the live format with:
    #   gh api repos/QianChenTT/pixiu/actions/oidc/customization/sub
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:QianChenTT@149524966/pixiu@1391471156:ref:refs/heads/main"]
    }
  }
}

# The role GitHub Actions becomes. It has no permissions yet: there is nothing for CI to
# deploy until the platform slice, and what it may do is decided then
resource "aws_iam_role" "deploy" {
  name               = "pixiu-github-deploy"
  description        = "Assumed by GitHub Actions runs on main of QianChenTT/pixiu"
  assume_role_policy = data.aws_iam_policy_document.deploy_trust.json
}

# The workflow needs the role's ARN. It holds the account ID, so it goes into a GitHub
# Actions secret. Read it with: terraform output -raw deploy_role_arn
output "deploy_role_arn" {
  value     = aws_iam_role.deploy.arn
  sensitive = true
}
