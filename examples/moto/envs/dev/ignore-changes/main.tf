resource "aws_sqs_queue" "ignore_changes_visibility" {
  tags                       = { stage = "dev" }
  name                       = "dev-ignore-changes-visibility"
  visibility_timeout_seconds = 30

  lifecycle {
    ignore_changes = [visibility_timeout_seconds]
  }
}
