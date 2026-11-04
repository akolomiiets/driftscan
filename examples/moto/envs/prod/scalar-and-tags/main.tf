resource "aws_sqs_queue" "scalar_attribute_drift" {
  name                       = "prod-scalar-attribute-drift"
  visibility_timeout_seconds = 30

  tags = {
    owner = "platform"
    stage = "prod"
  }
}

resource "aws_ssm_parameter" "scalar_description_drift" {
  tags        = { stage = "prod" }
  name        = "/prod/scalar-description-drift"
  type        = "String"
  value       = "hello"
  description = "managed by terraform"
}

resource "aws_sqs_queue" "map_tags_drift" {
  name = "prod-map-tags-drift"

  tags = {
    owner     = "platform"
    changed   = "before"
    to_remove = "yes"
  }
}
