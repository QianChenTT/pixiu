# The node: one EC2 instance running k3s, set up by its startup script

# What the startup script installs. Bumped by hand in a PR (threat model row 11): read the new
# release's sha256sum-arm64.txt and the GitHub release digest, and hash install.sh at the new tag
locals {
  k3s_version        = "v1.36.5+k3s1"
  k3s_arm64_sha256   = "135e34cb9e8a1cfae3cb55577789e93501efe7edc080a8b2630458a85b07721e"
  k3s_install_sha256 = "46177d4c99440b4c0311b67233823a8e8a2fc09693f6c89af1a7161e152fbfad"

  # The image by digest, never by tag
  image = "ghcr.io/qianchentt/pixiu@${var.image_digest}"
}

# Canonical publishes the newest Ubuntu 24.04 image ID for arm64 in this public parameter.
# Reading it at plan time means every new node starts from the newest patched image
data "aws_ssm_parameter" "ubuntu_ami" {
  name = "/aws/service/canonical/ubuntu/server/24.04/stable/current/arm64/hvm/ebs-gp3/ami-id"
}

resource "aws_instance" "node" {
  # insecure_value, not value: the provider hides every parameter's value in plans, and an image
  # ID is public. Shown, a plan that replaces the node says which image it moves to
  ami           = data.aws_ssm_parameter.ubuntu_ami.insecure_value
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

  # The startup script, filled in from the template. EC2 runs it once, on first boot, so a change
  # only takes effect on a new node: any change here (a new image digest above all) replaces the
  # instance instead of editing a script that would never run again
  user_data = templatefile("${path.module}/node/user-data.sh.tftpl", {
    k3s_version     = local.k3s_version
    k3s_version_url = urlencode(local.k3s_version)
    k3s_sha256      = local.k3s_arm64_sha256
    install_sha256  = local.k3s_install_sha256
    k3s_config      = file("${path.module}/node/k3s-config.yaml")
    psa             = file("${path.module}/node/psa.yaml")
    audit_policy    = file("${path.module}/node/audit-policy.yaml")
    # Prefixed so they can't collide with the files k3s writes to the same folder
    manifests = {
      "pixiu-namespace.yaml" = file("${path.module}/manifests/namespace.yaml")
      "pixiu-api.yaml"       = replace(file("${path.module}/manifests/api.yaml"), "$${image}", local.image)
    }
  })
  user_data_replace_on_change = true

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 20
    encrypted             = true
    delete_on_termination = true
  }

  tags = { Name = "pixiu-node" }
}
