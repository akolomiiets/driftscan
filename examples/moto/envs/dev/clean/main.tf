resource "aws_sqs_queue" "clean_nothing_changes" {
  name = "dev-clean-nothing-changes"

  tags = {
    stage = "dev"
  }
}
