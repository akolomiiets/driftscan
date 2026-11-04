# Required variable without a value: planning fails, so this Root is a Scan error. Never applied.
variable "required_without_value" {
  type = string
}

resource "aws_sqs_queue" "never_planned" {
  tags = { stage = "dev" }
  name = "dev-${var.required_without_value}"
}
