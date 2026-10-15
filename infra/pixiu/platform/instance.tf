# The node: one EC2 instance running k3s. Its startup script is added in the next file

# Canonical publishes the newest Ubuntu 24.04 image ID for arm64 in this public parameter.
# Reading it at plan time means every new node starts from the newest patched image
data "aws_ssm_parameter" "ubuntu_ami" {
  name = "/aws/service/canonical/ubuntu/server/24.04/stable/current/arm64/hvm/ebs-gp3/ami-id"
}

resource "aws_instance" "node" {
  ami           = data.aws_ssm_parameter.ubuntu_ami.value
  instance_type = "t4g.small"

  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.node.id]
  associate_public_ip_address = true

  # The role the node acts as in AWS: SSM only. Created in the bootstrap folder, so CI only
  # passes this one role and never creates IAM
  iam_instance_profile = "pixiu-node"

  # The metadata address: token required (the session-based version), and the reply's hop
  # limit 1 so it can't travel one network step further into a pod
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  # Burstable CPU: "standard" slows the node down when its credits run out instead of billing
  # for extra CPU, so a runaway process can't run up the bill (threat model row 9)
  credit_specification {
    cpu_credits = "standard"
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 20
    encrypted             = true
    delete_on_termination = true
  }

  tags = { Name = "pixiu-node" }
}
