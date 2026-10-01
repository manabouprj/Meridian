data "aws_availability_zones" "az" { state = "available" }

resource "aws_vpc" "v" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags                 = { Name = "vpc-${var.prefix}" }
}

resource "aws_subnet" "private" {
  count             = 3
  vpc_id            = aws_vpc.v.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, count.index)
  availability_zone = data.aws_availability_zones.az.names[count.index]
  tags              = { Name = "snet-${var.prefix}-private-${count.index}" }
}

resource "aws_subnet" "public" {
  count             = var.nat_gateway ? 1 : 0
  vpc_id            = aws_vpc.v.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, 200)
  availability_zone = data.aws_availability_zones.az.names[0]
  tags              = { Name = "snet-${var.prefix}-public" }
}

resource "aws_internet_gateway" "igw" {
  count  = var.nat_gateway ? 1 : 0
  vpc_id = aws_vpc.v.id
}

resource "aws_eip" "nat" {
  count  = var.nat_gateway ? 1 : 0
  domain = "vpc"
}

resource "aws_nat_gateway" "nat" {
  count         = var.nat_gateway ? 1 : 0
  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public[0].id
}

resource "aws_route_table" "public" {
  count  = var.nat_gateway ? 1 : 0
  vpc_id = aws_vpc.v.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw[0].id
  }
}

resource "aws_route_table_association" "public" {
  count          = var.nat_gateway ? 1 : 0
  subnet_id      = aws_subnet.public[0].id
  route_table_id = aws_route_table.public[0].id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.v.id
  dynamic "route" {
    for_each = var.nat_gateway ? [1] : []
    content {
      cidr_block     = "0.0.0.0/0"
      nat_gateway_id = aws_nat_gateway.nat[0].id
    }
  }
}

resource "aws_route_table_association" "private" {
  count          = 3
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# Internal ALB: HTTPS from the networks your users and remote MCP clients come from
resource "aws_security_group" "alb" {
  name   = "${var.prefix}-alb"
  vpc_id = aws_vpc.v.id
  ingress {
    description = "HTTPS to the console, API and MCP endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = length(var.client_cidrs) > 0 ? var.client_cidrs : [var.vpc_cidr]
  }
  egress {
    description = "to the api tasks"
    from_port   = 8090
    to_port     = 8090
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }
}

resource "aws_security_group" "app" {
  name   = "${var.prefix}-app"
  vpc_id = aws_vpc.v.id
  ingress {
    description     = "API only from the internal ALB"
    from_port       = 8090
    to_port         = 8090
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  ingress {
    description = "syslog (TCP) from the VPC / NLB / on-premises over VPN"
    from_port   = 5514
    to_port     = 5514
    protocol    = "tcp"
    cidr_blocks = length(var.syslog_cidrs) > 0 ? var.syslog_cidrs : [var.vpc_cidr]
  }
  ingress {
    description = "syslog (UDP) from the VPC / NLB / on-premises over VPN"
    from_port   = 5514
    to_port     = 5514
    protocol    = "udp"
    cidr_blocks = length(var.syslog_cidrs) > 0 ? var.syslog_cidrs : [var.vpc_cidr]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "endpoints" {
  name   = "${var.prefix}-vpce"
  vpc_id = aws_vpc.v.id
  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.v.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
}

# Interface endpoints keep AWS API traffic (and Bedrock inference in the same region) off the internet.
resource "aws_vpc_endpoint" "iface" {
  for_each            = toset(["sqs", "secretsmanager", "logs", "ecr.api", "ecr.dkr", "sts", "athena", "glue", "kms", "bedrock-runtime"])
  vpc_id              = aws_vpc.v.id
  service_name        = "com.amazonaws.${var.region}.${each.key}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true
}
