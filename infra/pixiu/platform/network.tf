# The network the node sits in. A VPC of our own rather than the account's default one, so
# every setting is in the code, reviewed and scanned

# 10.20.0.0/16: a private range that doesn't overlap a home network (usually 192.168.x.x),
# in case a VPN ever joins the two
resource "aws_vpc" "main" {
  cidr_block           = "10.20.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = false

  tags = { Name = "pixiu-platform" }
}

# One subnet in one availability zone: the node is a single machine, so a second zone would
# add nothing. Instances here get no public address unless the instance asks for one
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.20.1.0/24"
  availability_zone       = "ca-central-1a"
  map_public_ip_on_launch = false

  tags = { Name = "pixiu-platform-public" }
}

# The VPC's door to the internet
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = { Name = "pixiu-platform" }
}

# This route is what makes the subnet public: anything not inside the VPC goes to the gateway
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = { Name = "pixiu-platform-public" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# Every VPC comes with a default security group that lets its members reach each other on all
# ports. Nothing here uses it. Declaring it with no rules empties it, so anything attached to
# it by mistake gets no traffic at all
resource "aws_default_security_group" "main" {
  vpc_id = aws_vpc.main.id

  tags = { Name = "pixiu-platform-default-unused" }
}
