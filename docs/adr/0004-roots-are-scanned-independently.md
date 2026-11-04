# Roots are scanned independently, in no particular order

Apply order between Roots matters, but planning does not: a Root only reads other Roots' existing state through `terraform_remote_state`. So driftscan plans every Root independently and in parallel, with no dependency graph, and a Root that fails becomes a Scan error Finding without stopping the Scan. Large repos split a Scan across CI jobs with `--shard i/n`; Reports from shards are merged afterwards.

## Considered Options

- Dependency-ordered scanning (like mass-apply tools): needed for apply, pure cost for detection.

## Consequences

- Two commands: `driftscan scan` plans Roots and writes a raw Report; `driftscan report` merges one or more raw Reports, compares them with the Baseline and sends every output. Without shards `scan` does both.
- Defaults: 4 Roots in parallel, 15 minutes per Root; a timeout is a Scan error. Both are configurable.
- A shard Report is marked `partial`, and so is a merge that does not cover every shard of one split. In a partial Report, Baseline Findings of Roots that were not scanned stay `unknown`; only a complete Scan resolves the Findings of a Root that disappeared.
- Roots with a `cloud` block are skipped by discovery (HCP Terraform runs plans remotely, where saved plans are not supported) unless listed under `roots:`.

## Update (v0.3.0)

`report -complete` asserts that the given Reports together cover every Root (for example one per environment), so a merge of several unsharded Reports is no longer partial and Baseline Findings of absent Roots resolve. It does not override a known-incomplete shard split or a Report that is partial on its own. Without it, a merge of two or more unsharded Reports stays partial, because a lost matrix job is indistinguishable from an environment that was never scanned.
