# alb.tf in terraform/eks-cluster/

# APPLICATION LOAD BALANCER SECURITY GROUP
resource "aws_security_group" "alb_sg" {
    name        = "alb_security"
    description = "security group for alb"
    vpc_id      = aws_vpc.main.id

    tags = {
        Name = "${var.cluster_name}-alb-sg"
    }
}

# Allow HTTP traffic on port 80 from anywhere
resource "aws_vpc_security_group_ingress_rule" "alb_http_ingress" {
    security_group_id = aws_security_group.alb_sg.id
    cidr_ipv4         = "0.0.0.0/0"
    from_port         = 80
    to_port           = 80
    ip_protocol       = "tcp"
}

# Allow HTTPS traffic on port 443 from anywhere
resource "aws_vpc_security_group_ingress_rule" "alb_https_ingress" {
    security_group_id = aws_security_group.alb_sg.id
    cidr_ipv4         = "0.0.0.0/0"
    from_port         = 443
    to_port           = 443
    ip_protocol       = "tcp"
}

# Allow all outbound traffic (IPv4)
resource "aws_vpc_security_group_egress_rule" "alb_allow_all_egress" {
    security_group_id = aws_security_group.alb_sg.id
    cidr_ipv4         = "0.0.0.0/0"
    ip_protocol       = "-1" 
}

# Allows traffic from alb to worker on port 30080
resource "aws_vpc_security_group_ingress_rule" "worker_allow_alb_ingress" {
    security_group_id            = aws_security_group.worker_sg.id
    referenced_security_group_id = aws_security_group.alb_sg.id
    from_port                    = 30080
    to_port                      = 30080
    ip_protocol                  = "tcp"
}


# APPLICATION LOAD BALANCER RESOURCE
resource "aws_lb" "alb" {
    name               = "${var.cluster_name}-alb"
    internal           = false
    load_balancer_type = "application"
    security_groups    = [aws_security_group.alb_sg.id]
    subnets            = aws_subnet.public[*].id

    enable_deletion_protection = false

    tags = {
        Name = "${var.cluster_name}-alb"
    }
}

resource "aws_lb_listener" "http" {
    load_balancer_arn   = aws_lb.alb.arn
    port                = "80"
    protocol            = "HTTP"

    default_action {
        type             = "forward"
        target_group_arn = aws_lb_target_group.flask_tg.arn
    }  

}

/* resource "aws_lb_listener" "https" {
    load_balancer_arn = aws_lb.alb.arn
    port              = "443"
    protocol          = "HTTPS"
    ssl_policy        = "ELBSecurityPolicy-2016-08"
    certificate_arn   = aws_acm_certificate.example_cert.arn

    default_action {
        type             = "forward"
        target_group_arn = aws_lb_target_group.backend_tg.arn
    }
}
*/

resource "aws_lb_target_group" "flask_tg" {
  name     = "${var.cluster_name}-tg"
  port     = 30080             
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id
  target_type = "instance"

  health_check {
    path                = "/"
    protocol            = "HTTP"
    matcher             = "200"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 3
    unhealthy_threshold = 3
  }

  tags = {
    Name = "${var.cluster_name}-tg"
  }
}

# retreive instance id's from nodes
data "aws_instances" "worker_nodes" {
    filter {
        name = "tag:Name"
        values = ["tumor-prediction-nodes"]
    }
}

# create target group attachment
resource "aws_lb_target_group_attachment" "flask_tg_attachment" {
    count = length(data.aws_instances.worker_nodes.ids)
    target_group_arn = aws_lb_target_group.flask_tg.arn
    target_id = element(data.aws_instances.worker_nodes.ids, count.index)
    port      = 30080
}
