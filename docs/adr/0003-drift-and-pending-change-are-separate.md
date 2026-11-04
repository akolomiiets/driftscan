# Drift and Pending change come from two separate plans

Most drift tools treat any non-empty plan as drift. A normal `plan` cannot separate the two by itself: a manual change shows up in `resource_drift` and again in `resource_changes` as the update that would revert it. So driftscan runs two plans per Root after one `init`: a normal plan (refresh on) whose `resource_drift` gives Drift (reality vs state, ADR-0011 says which of it apply would revert) and `plan -refresh=false` gives Pending changes (code vs state). The second plan does not read managed resources, only data sources and provider auth, so it is cheap. Pending changes default to `info` Severity so they do not drown out Drift.

## Considered Options

- One normal plan, Pending = `resource_changes` minus drifted addresses: faster, but a resource with both Drift and a Pending change loses the Pending change. `relevant_attributes` is documented by Terraform as a UI hint only, not something to drive logic.
- Drift only in v1: simplest, but merged-and-never-applied changes are a real, common gap.
