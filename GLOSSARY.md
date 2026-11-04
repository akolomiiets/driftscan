# driftscan

Detects when real infrastructure no longer matches what Terraform/OpenTofu last recorded, and reports it with enough context for someone to act.

## Language

**Root**:
A directory that Terraform plans on its own: it declares a backend and owns one state. With configured workspaces, each workspace of that directory is its own Root, named `path@workspace`.
_Avoid_: workspace, stack, component, project

**Scan**:
One run of driftscan over a set of Roots, producing one Report.
_Avoid_: check, job, run

**Report**:
The full result of a Scan: every Finding plus per-Root outcome.
_Avoid_: result, output

**Finding**:
One reported fact about one resource (or one Root) in a Scan. Identified by Root, resource address and kind; the drifted attributes are not part of its identity.
_Avoid_: alert, issue, violation

### Kinds of Finding

**Drift**:
Real infrastructure differs from the Root's state, so something changed it outside Terraform.
_Avoid_: change, diff

**Pending change**:
The Root's code differs from its state, so a change was merged but not applied. Not Drift.
_Avoid_: drift, unapplied drift

**Scan error**:
A Root that could not be planned (init failure, credentials, provider error), so its Drift is unknown.
_Avoid_: failure, crash

### Judging Findings

**Severity**:
How urgently a Finding needs a human: critical, high, medium, low or info.
_Avoid_: priority, level

**Severity rule**:
A match on resource type and optionally attribute path that assigns a Severity.

**Ignore rule**:
A match that drops a Finding before it is reported, for known noise.
_Avoid_: suppression, exclusion

**Acknowledged**:
Drift only on attributes Terraform will not revert: ones the code tells it to ignore (`lifecycle.ignore_changes`) or ones the resource's configuration never sets (managed by another resource, or computed-only). Reported at info Severity, never as Drift that needs action. The reason is `ignore_changes`, `not_in_config` or `mixed`.

### Context on a Finding

**Owner**:
Who is responsible for the code of a Finding's Root, from CODEOWNERS or git history.

**Changed by**:
Who last changed the drifted resource outside Terraform, from the cloud provider's audit log.

**Advice**:
An AI-generated triage note on a Finding: likely cause and suggested action. A guess, never acted on.

### Across Scans

**Baseline**:
The Report of the previous Scan, given to the current Scan for comparison.
_Avoid_: previous state, history, snapshot

**Finding status**:
A Finding's relation to the Baseline: new, persisting, changed (persisting, but a different set of attributes drifted), resolved, or unknown (its Root had a Scan error, so it is carried over, never resolved).
_Avoid_: lifecycle, state
