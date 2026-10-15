# The role pull request runs take to plan the platform. Read-only on purpose: a pull request
# runs code nobody has reviewed yet (the workflow file and the Terraform are part of the PR),
# so whatever this role allows, anyone who can push a branch here can do

data "aws_iam_policy_document" "plan_trust" {
  statement {
    sid     = "GitHubPullRequestsOnly"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # A run for a pull request in this repo, on the same permanent IDs as the deploy role. Runs
    # from forks get no token at all, so this means branches pushed to this repo. A job that
    # names an environment gets an environment subject instead, so the plan job uses none
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:QianChenTT@149524966/pixiu@1391471156:pull_request"]
    }
  }
}

resource "aws_iam_role" "plan" {
  name               = "pixiu-github-plan"
  description        = "Assumed by pull request runs of QianChenTT/pixiu to plan the platform, read-only"
  assume_role_policy = data.aws_iam_policy_document.plan_trust.json
}

data "aws_iam_policy_document" "plan" {
  # Read the platform's resources back from AWS (the refresh). The list is the read half of
  # what iam-policy-autopilot found in the platform plan. EC2's Describe calls can't be
  # narrowed to resources, so they go on "*". DescribeInstanceAttribute can read the node's
  # user data, which holds no secrets
  statement {
    sid    = "ReadPlatformResources"
    effect = "Allow"
    actions = [
      "ec2:DescribeIamInstanceProfileAssociations",
      "ec2:DescribeImages",
      "ec2:DescribeInstanceAttribute",
      "ec2:DescribeInstanceCreditSpecifications",
      "ec2:DescribeInstanceTypes",
      "ec2:DescribeInstances",
      "ec2:DescribeInternetGateways",
      "ec2:DescribeLaunchTemplateVersions",
      "ec2:DescribeLaunchTemplates",
      "ec2:DescribeNetworkAcls",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeRouteTables",
      "ec2:DescribeSecurityGroupRules",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSpotInstanceRequests",
      "ec2:DescribeSubnets",
      "ec2:DescribeTags",
      "ec2:DescribeVolumes",
      "ec2:DescribeVolumesModifications",
      "ec2:DescribeVpcAttribute",
      "ec2:DescribeVpcs",
    ]
    resources = ["*"]
  }

  # The newest Ubuntu image ID, which the instance follows. A public parameter, so its ARN
  # has no account ID
  statement {
    sid       = "ReadUbuntuImageParameter"
    effect    = "Allow"
    actions   = ["ssm:GetParameter"]
    resources = ["arn:aws:ssm:ca-central-1::parameter/aws/service/canonical/ubuntu/server/24.04/stable/current/arm64/hvm/ebs-gp3/ami-id"]
  }

  # The state: list the bucket (shows object names only), read platform.tfstate and nothing
  # else. The bootstrap's own state in the same bucket stays out of reach
  statement {
    sid       = "ListStateBucket"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.state.arn]
  }

  statement {
    sid       = "ReadPlatformState"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.state.arn}/platform.tfstate"]
  }

  # A plan takes the lock while it runs, so the one write this role has is the lock object
  statement {
    sid       = "LockPlatformState"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = ["${aws_s3_bucket.state.arn}/platform.tfstate.tflock"]
  }
}

resource "aws_iam_role_policy" "plan" {
  name   = "plan-platform"
  role   = aws_iam_role.plan.id
  policy = data.aws_iam_policy_document.plan.json
}

# The plan workflow needs the role's ARN, which holds the account ID: a GitHub Actions secret.
# Read it with: terraform output -raw plan_role_arn
output "plan_role_arn" {
  value     = aws_iam_role.plan.arn
  sensitive = true
}
