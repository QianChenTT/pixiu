# The k3s node's identity in AWS. The platform's instance picks it by name (pixiu-node), so CI
# only ever hands this one role to EC2 and never creates IAM itself

# Only EC2 can take the role, and only for an instance started with its profile
data "aws_iam_policy_document" "node_trust" {
  statement {
    sid     = "Ec2Only"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "node" {
  name               = "pixiu-node"
  description        = "The pixiu k3s node: Session Manager only"
  assume_role_policy = data.aws_iam_policy_document.node_trust.json
}

# AWS's documented minimum for Session Manager: the agent's heartbeat and its message channels,
# which also carry Run Command. Not the managed AmazonSSMManagedInstanceCore, which also lets
# the node read every Parameter Store value in the account and pull State Manager documents.
# Anyone who gets a shell on the node holds these permissions
data "aws_iam_policy_document" "node_ssm" {
  statement {
    sid    = "SessionManagerOnly"
    effect = "Allow"
    actions = [
      "ssm:UpdateInstanceInformation",
      "ssmmessages:CreateControlChannel",
      "ssmmessages:CreateDataChannel",
      "ssmmessages:OpenControlChannel",
      "ssmmessages:OpenDataChannel",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "node_ssm" {
  name   = "session-manager"
  role   = aws_iam_role.node.id
  policy = data.aws_iam_policy_document.node_ssm.json
}

# The wrapper EC2 needs to attach a role to an instance. Same name as the role
resource "aws_iam_instance_profile" "node" {
  name = "pixiu-node"
  role = aws_iam_role.node.name
}
