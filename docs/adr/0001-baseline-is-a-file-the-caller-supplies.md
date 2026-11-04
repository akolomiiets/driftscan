# Baseline is a file the caller supplies

A stateless scan repeats the same Findings every night, which trains people to ignore it, so each Finding gets a status (new, persisting, resolved) against the previous Report. driftscan reads that Baseline from a path or URL and writes the new Report; where it is kept (CI artifact, bucket, git branch) is the caller's choice. driftscan has no storage backend of its own, so it needs no write credentials to anything.

## Considered Options

- Stateless: simplest, but every alert channel would need its own deduplication.
- Built-in S3/GCS backend: convenient, but adds cloud SDKs, write permissions and a second trust surface to a read-only tool.

## Consequences

- A Finding is identified by Root + resource address + kind. More attributes drifting on the same resource makes it `changed`, not a new Finding, so nothing looks fixed when it is not.
- A Root with a Scan error carries its Baseline Findings over as `unknown`; they are never marked resolved by a failed Scan.
- Slack gets only the delta (new, changed, resolved, Scan errors). `--fail-on` counts every active Finding, so a CI job stays red until drift is fixed.
- With no Baseline (first Scan) Slack gets one "baseline established: N Findings" message, not N alerts.
- The new Report is written to `-out` last. If Slack or OTLP delivery fails it goes to `<out>.undelivered` instead, so the Baseline does not advance past alerts nobody received.
