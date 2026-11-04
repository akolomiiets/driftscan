locals {
  # Keys with characters that need escaping in Markdown tables, HTML and workflow annotations.
  odd_keys = {
    "a|b"             = "pipe"
    "x<y"             = "angle"
    "dots.and spaces" = "dots"
    "quote\"d"        = "quote"
  }
}

resource "aws_sqs_queue" "odd_key" {
  tags     = { stage = "dev" }
  for_each = local.odd_keys

  name                       = "dev-odd-key-${each.value}"
  visibility_timeout_seconds = 30
}
