# The AI advisor sees only the Report

`driftscan advise` asks a model for a short triage note per Finding: likely cause, risk and a recommended action (adopt into code, revert, ignore with a drift.yaml snippet, or investigate). It is a separate command that reads a raw Report and sends only what the Report already holds (address, type, kind, attribute paths, severity, acknowledged, owner), never plan values or file contents, so ADR-0002 still holds and a model cannot leak what driftscan never kept. The first provider is Amazon Bedrock (Converse API) because the data then stays inside the user's own AWS account under their IAM and logging; the provider sits behind a small interface so an OpenAI-compatible or GitHub Models adapter can be added later. The model id is required and has no default, because model ids go stale. The advisor only writes text into the Report; it never runs anything (ADR-0006).

## Consequences

- Advice is a guess from names alone: it cannot say what a value changed to, so Markdown and Slack label it AI-generated and unverified.
- Only `advise` needs `bedrock:InvokeModel` and the AWS SDK code path; `scan` and `report` still make no cloud calls (ADR-0007), though the SDK is linked into the same binary.
- Cost is bounded by `-max-findings` (default 50, most severe first), one request per Root per 15 Findings, and info and acknowledged Findings are skipped unless asked for.
- Model output is untrusted: answers that are not valid JSON, name an unknown Finding or use an unknown action are dropped, and notes are capped at 400 characters.
