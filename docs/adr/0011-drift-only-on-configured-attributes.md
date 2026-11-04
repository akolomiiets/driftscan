# Drift counts only on attributes the configuration sets

`plan -refresh-only` reports every attribute that differs from state, including ones the resource's code never sets: rules and policies managed by separate resources (`aws_vpc_security_group_ingress_rule`, `aws_iam_role_policy`, `aws_s3_bucket_*`) and computed-only attributes. Terraform will never revert these, so they are noise. A drifted attribute path whose top-level attribute or block name is not set in the resource's configuration is "not managed by this resource"; when all drifted paths of a Finding are either in `lifecycle.ignore_changes` or not set in configuration, the Finding is acknowledged (info Severity) with `ack_reason` of `ignore_changes`, `not_in_config` or `mixed`. "Set" comes from the plan JSON `configuration` section (`expressions` keys, following `module_calls` and ignoring instance keys), so it works for local, registry and git modules without reading their sources. Terraform's `expressions` excludes `dynamic` blocks, so a root-module resource's dynamic block names are read from its HCL, and a block-shaped value on a module resource is kept as Drift because it may be a dynamic block.

## Consequences

- When the configuration section or the resource in it is missing, or a path cannot be read, the attribute counts as set and the Finding stays Drift.
- Known limitation: an attribute with a provider schema default that the config does not set would be reverted by `apply`, but is marked `not_in_config`.
- A rule added in the console to a resource whose rules are managed elsewhere (for example an inline ingress rule on a security group using separate rule resources) becomes info, not Drift.
- Block-shaped drift on module resources (for example `inline_policy` in a module) is not acknowledged; this is the price of not reading module sources.
- Still no attribute values in any output (ADR-0002); `ack_reason` is a fixed enum.
