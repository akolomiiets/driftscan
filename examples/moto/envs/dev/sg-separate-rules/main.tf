resource "aws_vpc" "main" {
  tags       = { stage = "dev" }
  cidr_block = "10.20.0.0/16"
}

# No inline ingress: rules are separate resources, so a rule added outside Terraform is not reverted by apply.
resource "aws_security_group" "separate_rules_not_reverted" {
  tags   = { stage = "dev" }
  name   = "dev-separate-rules-not-reverted"
  vpc_id = aws_vpc.main.id
}

resource "aws_vpc_security_group_ingress_rule" "https" {
  tags              = { stage = "dev" }
  security_group_id = aws_security_group.separate_rules_not_reverted.id
  cidr_ipv4         = "10.0.0.0/8"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}
