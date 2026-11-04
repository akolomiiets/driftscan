# Detect and report only

driftscan does not remediate: no apply, no generated HCL, no auto-opened PRs, no HTTP server mode. Fixing drift is a decision (revert reality or adopt it into code) that belongs to a human going through normal review, and every write path would break ADR-0002. Outputs in v1 are JSON Report, Markdown summary, Slack, metrics and SARIF.

Metrics are emitted over OTLP/HTTP only. An optional AI advisor (any provider the user configures) is a post-v1 output: it receives only redacted Findings and explains risk and next step, it never sees values and never changes anything.

SARIF results point at the `resource` block found by parsing the Root's HCL; resources inside modules point at the calling `module` block, and anything unresolved points at the Root's backend file.
