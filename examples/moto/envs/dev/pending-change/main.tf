variable "retention_seconds" {
  type    = number
  default = 86400
}

# drift.yaml sets TF_VAR_retention_seconds for this Root at scan time only, which looks like merged,
# unapplied code: a Pending change, not Drift.
resource "aws_sqs_queue" "pending_config_edit" {
  tags                      = { stage = "dev" }
  name                      = "dev-pending-config-edit"
  message_retention_seconds = var.retention_seconds
}
