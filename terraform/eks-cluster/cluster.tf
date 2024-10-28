# cluster.tf in terraform/eks-cluster/

# EKS CLUSTER MODULE 

module "eks" {
    source          = "terraform-aws-modules/eks/aws"
    version         = "~> 20.0" 
    
    cluster_name    = var.cluster_name
    cluster_version = var.kubernetes_version
    vpc_id          = aws_vpc.main.id
    subnet_ids      = aws_subnet.private[*].id
    
    cluster_endpoint_private_access = true
    cluster_endpoint_public_access  = true
    enable_cluster_creator_admin_permissions = true 

    cluster_security_group_id = aws_security_group.eks_cluster_sg.id

    iam_role_arn = aws_iam_role.eks_cluster_role.arn 

    cluster_addons = {
        coredns = {
        resolve_conflicts = "OVERWRITE"
        version           = "v1.11.1-eksbuild.9"
        }
        kube-proxy = {
        resolve_conflicts = "OVERWRITE"
        version           = "v1.30.0-eksbuild.3"
        }
    }
        tags = {
            Environment = "production"
            Project     = "tumor-prediction"
        }

}


module "eks_managed_node_group" {
  source = "terraform-aws-modules/eks/aws//modules/eks-managed-node-group"

  cluster_name    = module.eks.cluster_name
  instance_types  = [var.instance_type]
  desired_size    = var.desired_capacity
  min_size        = var.min_size
  max_size        = var.max_size

  subnet_ids      = aws_subnet.private[*].id
  cluster_service_cidr   = "172.20.0.0/16"

  iam_role_arn    = aws_iam_role.eks_node_role.arn

  name = "tumor-prediction-nodes"
  
  cluster_primary_security_group_id = module.eks.cluster_primary_security_group_id
  vpc_security_group_ids = [aws_security_group.worker_sg.id]

  tags = {
    Environment = "production"
    Project     = "tumor-prediction"
    Name        = "tumor-prediction-nodes"
  }
}


# EKS CLUSTER SECURITY GROUP
resource "aws_security_group" "eks_cluster_sg" {
    name = "cluster_security"
    description = "security group for cluster"
    vpc_id = aws_vpc.main.id

    tags = {
        Name = "${var.cluster_name}-eks-cluster-sg"
    }

}

# CONFIGURE SECURITY GROUPS    

# WORKER NODE SECURITY GROUP
resource "aws_security_group" "worker_sg" {
    name = "worker_node_security"
    description = "security group for worker nodes"
    vpc_id = aws_vpc.main.id

    tags = {
        Name = "${var.cluster_name}-worker-sg"
    }
}

# allows api access 
# temporarily set to accepting traffic from everywhere
resource "aws_vpc_security_group_ingress_rule" "primary_api_ingress" {
    security_group_id = module.eks.cluster_primary_security_group_id
    from_port         = 6443
    to_port           = 6443
    ip_protocol       = "tcp"
    cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_ingress_rule" "primary_kubelet_ingress" {
    security_group_id = aws_security_group.eks_cluster_sg.id
    referenced_security_group_id = aws_security_group.eks_cluster_sg.id
    from_port                    = 2379
    to_port                      = 2380
    ip_protocol                  = "tcp"
}

# opens port 10250 on worker nodes for traffic from control plane  
resource "aws_vpc_security_group_ingress_rule" "worker_kubelet_api_ingress" {
    security_group_id            = aws_security_group.worker_sg.id
    referenced_security_group_id = aws_security_group.eks_cluster_sg.id
    from_port                    = 10250
    to_port                      = 10250
    ip_protocol                  = "tcp"
}

# Allow outbound traffic on port 10250 to worker nodes
resource "aws_vpc_security_group_egress_rule" "control_plane_to_worker_kubelet" {
    security_group_id            = aws_security_group.eks_cluster_sg.id
    referenced_security_group_id = aws_security_group.worker_sg.id
    from_port                    = 10250
    to_port                      = 10250
    ip_protocol                  = "tcp"
}

# used internally for kube-controller-manager
resource "aws_vpc_security_group_ingress_rule" "control_plane_10257_ingress" {
    security_group_id            = aws_security_group.eks_cluster_sg.id
    referenced_security_group_id = aws_security_group.eks_cluster_sg.id
    from_port                    = 10257
    to_port                      = 10257
    ip_protocol                  = "tcp"
}

# used internally for kube-scheduler
resource "aws_vpc_security_group_ingress_rule" "control_plane_10259_ingress" {
    security_group_id            = aws_security_group.eks_cluster_sg.id
    referenced_security_group_id = aws_security_group.eks_cluster_sg.id
    from_port                    = 10259
    to_port                      = 10259
    ip_protocol                  = "tcp"
}

# used by worker node and alb 
resource "aws_vpc_security_group_ingress_rule" "worker_kube_proxy_ingress" {
  security_group_id            = aws_security_group.worker_sg.id
  referenced_security_group_id = aws_security_group.worker_sg.id
  from_port                    = 10256
  to_port                      = 10256
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "worker_to_control_plane_https" {
    security_group_id            = aws_security_group.worker_sg.id
    referenced_security_group_id = aws_security_group.eks_cluster_sg.id
    from_port                    = 443
    to_port                      = 443
    ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "worker_dns_udp" {
    security_group_id = aws_security_group.worker_sg.id
    from_port         = 53
    to_port           = 53
    ip_protocol       = "udp"
    cidr_ipv4         = "192.168.0.2/32"
}

resource "aws_vpc_security_group_egress_rule" "worker_dns_tcp" {
    security_group_id = aws_security_group.worker_sg.id
    from_port         = 53
    to_port           = 53
    ip_protocol       = "tcp"
    cidr_ipv4         = "192.168.0.2/32"
}