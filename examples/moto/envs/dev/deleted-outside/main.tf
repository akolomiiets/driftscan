resource "aws_sqs_queue" "deleted_outside_terraform" {
  tags = { stage = "dev" }
  name = "dev-deleted-outside-terraform"
}
