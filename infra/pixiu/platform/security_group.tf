# The node's firewall. No inbound rule at all: nothing on the internet can open a connection to
# the node. SSM works anyway, because the agent dials out and a security group lets the replies
# to an outbound connection back in

resource "aws_security_group" "node" {
  name        = "pixiu-node"
  description = "k3s node: no inbound, outbound HTTPS and HTTP only"
  vpc_id      = aws_vpc.main.id

  tags = { Name = "pixiu-node" }
}

# HTTPS out: the SSM agent, GHCR for the image, the k3s download, Ubuntu's security updates
# Accepted until 2027-01-14: outbound is limited by port, not by destination. Limiting destinations needs a
# domain-aware egress filter (AWS Network Firewall or a proxy), out of proportion for one lab node
#trivy:ignore:AWS-0104:exp:2027-01-14
resource "aws_vpc_security_group_egress_rule" "https" {
  security_group_id = aws_security_group.node.id
  description       = "HTTPS to anywhere"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

# HTTP out: Ubuntu's package mirrors on EC2 are served over plain HTTP (the packages are signed,
# so apt checks them anyway)
# Accepted until 2027-01-14: outbound is limited by port, not by destination. Limiting destinations needs a
# domain-aware egress filter (AWS Network Firewall or a proxy), out of proportion for one lab node
#trivy:ignore:AWS-0104:exp:2027-01-14
resource "aws_vpc_security_group_egress_rule" "http" {
  security_group_id = aws_security_group.node.id
  description       = "HTTP to anywhere, for the Ubuntu package mirror"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
  cidr_ipv4         = "0.0.0.0/0"
}
