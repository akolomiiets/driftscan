# Drift is actionable only if apply would revert it

A refresh-only plan reports every attribute that differs from state, including ones Terraform will never touch: rules and policies managed by separate resources (`aws_vpc_security_group_ingress_rule`, `aws_iam_role_policy`, `aws_s3_bucket_*`), computed-only attributes, `ignore_changes`. Deciding from the configuration which of those are safe is not exact, because provider defaults, `default_tags` and `dynamic` blocks are not visible there. So driftscan asks Terraform: the drift plan is a normal `plan` (refresh on, `-lock=false`), whose `resource_drift` lists what changed outside Terraform and whose `resource_changes` lists what apply would do. For each drifted resource, the Finding is acknowledged (info Severity) when the plan has no change on it, or an update touching none of the drifted attribute paths (a path overlaps when one is a segment-aligned prefix of the other). Otherwise it is real Drift, including when the plan deletes, creates or replaces the resource. Drift fully covered by `lifecycle.ignore_changes` keeps the more informative reason. `ack_reason` is `ignore_changes` or `not_reverted`.

## Consequences

- Exact for any provider and any infra: defaults, `default_tags`, attributes managed elsewhere and computed-only attributes all follow from what Terraform itself would do. No configuration or module sources are read.
- A normal plan can surface drift on a resource that a pending code change also touches; if the plan's update overlaps the drifted paths, it counts as actionable.
- A console-added rule on a resource whose rules are managed elsewhere is acknowledged as `not_reverted`, since apply would leave it.
- The plan needs the same read-only permissions as before (ADR-0002) and no lock; the plan file is deleted after `show -json`.
- Still no attribute values in any output; `ack_reason` is a fixed enum.
