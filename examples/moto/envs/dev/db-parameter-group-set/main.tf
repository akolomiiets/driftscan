# parameter blocks form a set: drift is reported at positional paths like parameter[N].name/value/apply_method,
# and one change shifts the indices of the elements after it.
resource "aws_db_parameter_group" "parameter_set_drift" {
  tags   = { stage = "dev" }
  name   = "dev-parameter-set-drift"
  family = "postgres15"

  parameter {
    name         = "log_connections"
    value        = "1"
    apply_method = "immediate"
  }

  parameter {
    name         = "log_disconnections"
    value        = "1"
    apply_method = "immediate"
  }

  parameter {
    name         = "log_min_duration_statement"
    value        = "500"
    apply_method = "immediate"
  }

  parameter {
    name         = "max_connections"
    value        = "200"
    apply_method = "pending-reboot"
  }

  parameter {
    name         = "shared_preload_libraries"
    value        = "pg_stat_statements"
    apply_method = "pending-reboot"
  }
}
