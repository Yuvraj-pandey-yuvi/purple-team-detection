resource "aws_instance" "purple_project" {
  ami                    = "ami-05d62b9bc5a6ca605"
  instance_type          = "t3.micro"
  key_name               = "buddyssh"
  subnet_id              = "subnet-0132054950bdd5619"
  vpc_security_group_ids = [aws_security_group.purple_project_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_ssm_profile.name

  tags = {
    Name = "purple-project"
  }
}

resource "aws_security_group" "purple_project_sg" {
  name        = "default"
  description = "default VPC security group"
  vpc_id      = "vpc-02d7cb89a994e3c41"
  # No inline ingress/egress here anymore — every rule below is its own
  # standalone resource, so honeypot exposure can be toggled independently
  # of dashboard/ssh access, and none of these fight each other on apply.
}

resource "aws_vpc_security_group_ingress_rule" "dashboard" {
  security_group_id = aws_security_group.purple_project_sg.id
  description        = "dashboard"
  from_port          = 8000
  to_port             = 8000
  ip_protocol        = "tcp"
  cidr_ipv4          = "0.0.0.0/0"
}

resource "aws_vpc_security_group_ingress_rule" "ssh" {
  security_group_id = aws_security_group.purple_project_sg.id
  description        = "ssh"
  from_port          = 22
  to_port             = 22
  ip_protocol        = "tcp"
  cidr_ipv4          = "0.0.0.0/0"
}

resource "aws_vpc_security_group_ingress_rule" "cowrie_ssh_honeypot" {
  security_group_id = aws_security_group.purple_project_sg.id
  description        = "cowrie honeypot ssh bait — deliberately open to all, this is the point"
  from_port          = 2222
  to_port             = 2222
  ip_protocol        = "tcp"
  cidr_ipv4          = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "allow_all_outbound" {
  security_group_id = aws_security_group.purple_project_sg.id
  ip_protocol        = "-1"
  cidr_ipv4          = "0.0.0.0/0"
}

resource "aws_iam_role" "ec2_ssm_role" {
  name = "ec2-ssm-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  description = "Allows EC2 instances to call AWS services on your behalf."
}

resource "aws_iam_instance_profile" "ec2_ssm_profile" {
  name = "ec2-ssm-role"
  role = aws_iam_role.ec2_ssm_role.name
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.ec2_ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}
