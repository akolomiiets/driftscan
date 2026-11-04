resource "aws_vpc" "main" {
  tags       = { stage = "dev" }
  cidr_block = "10.10.0.0/16"
}

# Inline ingress blocks form a set: drift is reported at positional paths like ingress[N].*
resource "aws_security_group" "inline_ingress_set_drift" {
  tags   = { stage = "dev" }
  name   = "dev-inline-ingress-set-drift"
  vpc_id = aws_vpc.main.id

  ingress {
    description = "http"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  ingress {
    description = "https"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  ingress {
    description = "ssh"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.1.0.0/16"]
  }
}
