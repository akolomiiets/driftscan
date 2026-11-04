resource "aws_sqs_queue" "clean_nothing_changes" {
  name = "prod-clean-nothing-changes"

  tags = {
    stage = "prod"
  }
}
