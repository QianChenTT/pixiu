# What the deploy role may do: create, change and delete exactly the platform's resources.
# Started from iam-policy-autopilot's draft of the platform plan, then trimmed of features the
# platform doesn't use, given the deletes a replace or destroy needs (from AWS's Service
# Authorization Reference) and limited to passing one role

data "aws_caller_identity" "current" {}

locals {
  ec2_arn = "arn:aws:ec2:ca-central-1:${data.aws_caller_identity.current.account_id}"
}

data "aws_iam_policy_document" "deploy" {
  # The calls that can be limited to resource types in this account and region
  statement {
    sid    = "ChangePlatformResources"
    effect = "Allow"
    actions = [
      # Network
      "ec2:CreateVpc",
      "ec2:ModifyVpcAttribute",
      "ec2:DeleteVpc",
      "ec2:CreateSubnet",
      "ec2:ModifySubnetAttribute",
      "ec2:DeleteSubnet",
      "ec2:CreateInternetGateway",
      "ec2:AttachInternetGateway",
      "ec2:DetachInternetGateway",
      "ec2:DeleteInternetGateway",
      "ec2:CreateRouteTable",
      "ec2:CreateRoute",
      "ec2:ReplaceRoute",
      "ec2:DeleteRoute",
      "ec2:DisassociateRouteTable",
      "ec2:DeleteRouteTable",
      # Security groups. No AuthorizeSecurityGroupIngress: the platform has no inbound rule,
      # so this role can't open the node to the internet. Revoking ingress stays, because
      # emptying the default security group removes its built-in inbound rule
      "ec2:CreateSecurityGroup",
      "ec2:DeleteSecurityGroup",
      "ec2:AuthorizeSecurityGroupEgress",
      "ec2:RevokeSecurityGroupEgress",
      "ec2:RevokeSecurityGroupIngress",
      "ec2:ModifySecurityGroupRules",
      # The node. TerminateInstances is what a new image digest needs: the node is replaced
      "ec2:TerminateInstances",
      "ec2:StopInstances",
      "ec2:StartInstances",
      "ec2:ModifyInstanceAttribute",
      "ec2:ModifyInstanceMetadataOptions",
      "ec2:ModifyInstanceCreditSpecification",
      "ec2:ModifyNetworkInterfaceAttribute",
      "ec2:ModifyVolume",
      "ec2:AssociateIamInstanceProfile",
      "ec2:DisassociateIamInstanceProfile",
      "ec2:ReplaceIamInstanceProfileAssociation",
    ]
    resources = [
      "${local.ec2_arn}:vpc/*",
      "${local.ec2_arn}:subnet/*",
      "${local.ec2_arn}:internet-gateway/*",
      "${local.ec2_arn}:route-table/*",
      "${local.ec2_arn}:security-group/*",
      "${local.ec2_arn}:security-group-rule/*",
      "${local.ec2_arn}:instance/*",
      "${local.ec2_arn}:network-interface/*",
      "${local.ec2_arn}:volume/*",
    ]
  }

  # The calls EC2 can't limit to resources: starting an instance (it touches an image, a
  # subnet, a security group, a volume and a network interface at once), tagging, attaching
  # the route table and every read
  statement {
    sid    = "Ec2CallsWithoutResourceLimits"
    effect = "Allow"
    actions = [
      "ec2:RunInstances",
      "ec2:AssociateRouteTable",
      "ec2:CreateTags",
      "ec2:DeleteTags",
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

  # Hand the node its role, and only that role. With "*" here, CI could start an instance
  # with any role EC2 can take and act as that role from the instance
  statement {
    sid       = "PassOnlyTheNodeRole"
    effect    = "Allow"
    actions   = ["iam:PassRole"]
    resources = [aws_iam_role.node.arn]

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["ec2.amazonaws.com"]
    }
  }

  # The newest Ubuntu image ID, which the instance follows
  statement {
    sid       = "ReadUbuntuImageParameter"
    effect    = "Allow"
    actions   = ["ssm:GetParameter"]
    resources = ["arn:aws:ssm:ca-central-1::parameter/aws/service/canonical/ubuntu/server/24.04/stable/current/arm64/hvm/ebs-gp3/ami-id"]
  }

  # The state: read and write platform.tfstate and its lock, nothing else in the bucket. No
  # delete on the state itself, Terraform never deletes it
  statement {
    sid       = "ListStateBucket"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.state.arn]
  }

  statement {
    sid       = "WritePlatformState"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["${aws_s3_bucket.state.arn}/platform.tfstate"]
  }

  statement {
    sid       = "LockPlatformState"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = ["${aws_s3_bucket.state.arn}/platform.tfstate.tflock"]
  }
}

resource "aws_iam_role_policy" "deploy" {
  name   = "apply-platform"
  role   = aws_iam_role.deploy.id
  policy = data.aws_iam_policy_document.deploy.json
}
