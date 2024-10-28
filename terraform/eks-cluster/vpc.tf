# vpc.tf in eks-cluster directory

resource "aws_vpc" "main" {
  cidr_block = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.cluster_name}-vpc"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.cluster_name}-igw"
  }
}

resource "aws_subnet" "public" {
    count               = 2
    vpc_id              = aws_vpc.main.id
    cidr_block          = var.public_subnets[count.index]
    availability_zone   = var.availability_zones[count.index]
    map_public_ip_on_launch = true 

    tags = {
        Name = "${var.cluster_name}-public-${count.index}"
    }
}

resource "aws_route_table" "public" {
    vpc_id = aws_vpc.main.id

    tags = {
        Name = "${var.cluster_name}-public-rt"
    }
}

resource "aws_route_table_association" "public" {
    count           = 2
    subnet_id       = aws_subnet.public[count.index].id
    route_table_id  = aws_route_table.public.id
}

resource "aws_route" "public_internet_access" {
    route_table_id      = aws_route_table.public.id 
    destination_cidr_block   = "0.0.0.0/0"
    gateway_id              = aws_internet_gateway.igw.id
}
                                                                
# PRIVATE SUBNETS

resource "aws_subnet" "private" {
    count              = 2 
    vpc_id             = aws_vpc.main.id
    cidr_block         = var.private_subnets[count.index]
    availability_zone  = var.availability_zones[count.index]

    tags = {
        Name = "${var.cluster_name}-private-${count.index}"
    }
}

resource "aws_route_table" "private" {
    vpc_id = aws_vpc.main.id
    
    tags   = {
        Name = "${var.cluster_name}-private-rt"
    }
}

resource "aws_route_table_association" "private" {
    count           = 2
    subnet_id       = aws_subnet.private[count.index].id
    route_table_id  = aws_route_table.private.id
}

resource "aws_route" "private_internet_access" {
    route_table_id          = aws_route_table.private.id 
    destination_cidr_block  = "0.0.0.0/0"
    nat_gateway_id          = aws_nat_gateway.nat.id
}


provider "aws" {
    region = var.aws_region
}

resource "aws_nat_gateway" "nat" {
    allocation_id = aws_eip.nat.id
    subnet_id     = aws_subnet.public[0].id

    tags = {
        Name = "${var.cluster_name}-nat"
    }
}

resource "aws_eip" "nat" {
    domain = "vpc"
}


