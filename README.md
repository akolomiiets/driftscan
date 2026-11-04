# driftscan

Detects Terraform/OpenTofu drift across every Root in a repository and alerts only on what changed
since the last Scan.

- **Drift vs Pending change.** Two plans per Root: a normal plan finds what changed outside
  Terraform (`resource_drift`), `plan -refresh=false` finds merged code that was never applied.
- **Quiet by design.** Each Finding is compared with the previous Report (the Baseline): Slack gets
  only new, changed and resolved Findings. A failed Scan never marks anything resolved.
- **Read-only.** No state lock, no apply, no remediation. Only resource addresses and attribute
  *paths* leave the tool; attribute values never do.
- **One static binary** with build provenance. No runtime package installs.

Status: pre-release. `advise` and `unmanaged` are experimental. Design: [GLOSSARY.md](GLOSSARY.md), [docs/adr](docs/adr).

## Quick start

```sh
driftscan scan -C path/to/repo -list                  # which Roots would be scanned
driftscan scan -C path/to/repo -baseline prev.json -out report.json
```

A Root is any directory whose `.tf` files declare a `backend` block. Each one is planned with the
credentials in your environment plus any `env` rule from `drift.yaml`.

Exit codes: `0` ok, `1` an active Finding at or above `-fail-on` (default `high`), `2` error.

## GitHub Actions

```yaml
name: drift
on:
  schedule:
    - cron: "0 3 * * *"
  workflow_dispatch:

permissions:
  contents: read
  id-token: write        # OIDC to your cloud, read-only role
  actions: read          # download the previous Baseline
  security-events: write # upload-sarif; drop both if you do not use Code Scanning

jobs:
  drift:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: hashicorp/setup-terraform@v4
        with:
          terraform_wrapper: false
      # configure read-only cloud credentials here (OIDC)
      - name: Previous Baseline
        continue-on-error: true
        env:
          GH_TOKEN: ${{ github.token }}
        # Newest artifact by name, not the last green run: a run with drift exits 1 but its Report
        # is still the Baseline.
        run: |
          run_id=$(gh api "repos/$GITHUB_REPOSITORY/actions/artifacts?name=driftscan-baseline&per_page=1" -q '.artifacts[0].workflow_run.id')
          if [ -n "$run_id" ]; then gh run download "$run_id" -n driftscan-baseline; fi
      - uses: akolomiiets/driftscan@v0.2.0
        with:
          version: v0.2.0
          args: scan -baseline driftscan-report.json -out driftscan-report.json -sarif drift.sarif -slack
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.DRIFT_SLACK_WEBHOOK }}
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: drift.sarif
      - uses: actions/upload-artifact@v7
        if: always()
        with:
          name: driftscan-baseline
          path: driftscan-report.json
          if-no-files-found: ignore
```

The Report is the next Baseline. Where you keep it (artifact, bucket, branch) is up to you.
If Slack or OTLP delivery fails the Report goes to `driftscan-report.json.undelivered` instead, so
the next run alerts again.

Large repos: run `scan -shard i/n -raw-out raw-i.json` in a matrix job, then
`driftscan report -baseline ... raw-*.json` in one job. A merge missing a shard is marked partial and
does not resolve anything for the Roots it did not see.

## Owners (`enrich`)

`driftscan enrich` adds an owner to each Finding of a raw Report, so Markdown and Slack show who to ask.
It uses CODEOWNERS (last matching rule wins, as on GitHub) and, with `-git-owner`, falls back to the
last commit author of the Root directory (needs full history: use `fetch-depth: 0` in `actions/checkout`; on a
shallow clone every owner would be the last merger and driftscan warns on stderr). Run it between `scan -raw-out` and `report`:

```sh
driftscan scan -C terraform -raw-out raw.json
driftscan enrich -repo . -prefix terraform -git-owner raw.json
driftscan report -baseline prev.json -out report.json -slack raw.json
```

With `-cloudtrail` (off by default) it also sets who last changed each drifted AWS resource: the newest
CloudTrail write event within the last 90 days (the causing change happened before the Drift was detected, so
the lookback does not start at the first Scan that saw it), shown as "Changed by" in Markdown
and Slack. Pass the same `-C` and `-config` as `scan`; enrich re-inits each drifted Root and reads `id` and `arn`
from its state in memory only, so the Report stays free of values (ADR-0008). Permissions: read access to the state
and the same terraform credentials as `scan`, plus `cloudtrail:LookupEvents` (one client per distinct `AWS_PROFILE` and
`AWS_REGION` in the Root's `env:`, else the default AWS credential chain and region; CloudTrail is regional, so set
`AWS_REGION` to the resource's region). Lookups are limited to 2 requests per second;
a failed lookup is a warning, not an error.

```sh
driftscan enrich -C terraform -cloudtrail -repo . -prefix terraform raw.json
```

## AI advice (`advise`) - experimental

Not yet run against a real Bedrock account; flags and output may change.

`driftscan advise` adds a short AI-generated triage note to each drifted Finding: likely cause, risk and
a recommended action (`adopt` into code, `revert` by applying, `ignore` with a drift.yaml snippet, or
`investigate`). It sends only what the Report holds (address, type, kind, attribute names, severity,
owner), never attribute values or file contents, and it never changes anything. Notes are guesses, shown
as "AI-generated" in Markdown and as an `[AI: action]` tag in Slack.

It calls the Amazon Bedrock Converse API with your default AWS credentials and region, so the data stays
in your account. The identity needs `bedrock:InvokeModel` on the model. The model id is required; check
the current id in the Bedrock console (many models need an inference profile id).

```sh
driftscan scan -C terraform -raw-out raw.json
driftscan enrich -repo . -prefix terraform raw.json
driftscan advise -C terraform -model <bedrock-model-id> raw.json
driftscan report -baseline prev.json -out report.json -slack raw.json
```

or in drift.yaml: `advisor: { model: <bedrock-model-id> }` (for example an Anthropic Claude model id or
inference profile id from the console). Flags: `-max-findings` (default 50 in total, most severe first),
`-include-info`, `-include-acknowledged`, `-out`. One request is sent per Root for up to 15 Findings;
malformed answers are dropped, a response cut off at max_tokens fails that request, and notes are capped at
400 characters. If any request fails the Report is still written but the exit code is 2. Findings that already
have advice are skipped, so a rerun does not resend them. `-max-findings` must be greater than 0. See ADR-0009.

## drift.yaml

Optional, read from the scanned directory. Every key has a default.

```yaml
binary: terraform          # or tofu
concurrency: 4
timeout: 15m               # per Root; a timeout is a Scan error
include: ["**"]            # globs over Root paths
exclude: ["legacy/**"]     # added to the defaults: **/.terraform/**, **/examples/**, **/testdata/**
roots: ["tools/local-state"]   # add Roots without a backend, or with a cloud block

workspaces:                # one Root per workspace, reported as "path@name"; last match wins
  - match: "envs/app"
    names: [default, staging]

env:                       # later rules win; a workspace Root matches "path" and "path@name"
  - match: "envs/prod/**"
    vars: { AWS_PROFILE: prod-readonly }

pending:
  enabled: true
  severity: info

severity:
  defaults: true           # built-in AWS/Azure/GCP rules (IAM, firewalls, KMS... high; tag-only info)
  rules:                   # last match wins
    - type: "aws_lambda_function"
      attribute: "source_code_hash"
      severity: low
    - type: "aws_iam_*"
      kind: pending
      severity: high

ignore:                    # every rule needs a reason; expires is optional (YYYY-MM-DD)
  - type: aws_autoscaling_group
    attribute: desired_capacity
    reason: scaled by policy
  - address: "aws_instance.legacy[0]"
    reason: migration TICKET-123
    expires: 2026-12-31
  - root: "envs/sandbox/**"        # also by Root path (path@workspace for workspace Roots)
    reason: playground, drift expected

advisor:                   # driftscan advise
  model: <bedrock-model-id>

noise:
  digest_after: 7          # with -digest, also alert persisting Findings seen 7+ times
  broken_root_after: 3     # remind once when a Root has failed 3 Scans in a row

slack:
  webhook_env: SLACK_WEBHOOK_URL
  group_by: scan           # or root

otlp:                      # with -otlp: driftscan.findings, driftscan.root.up, driftscan.scan.duration
  endpoint_env: DRIFTSCAN_OTLP_ENDPOINT   # e.g. https://otlp.example.com/v1/metrics
  headers_env: DRIFTSCAN_OTLP_HEADERS     # "Authorization=Basic ..."
```

## Acknowledged drift

Some drift is not worth acting on because applying the code would not undo it: attributes in
`lifecycle.ignore_changes`, rules managed by separate resources (for example `aws_vpc_security_group_ingress_rule`
for an `aws_security_group`), computed-only attributes. driftscan asks Terraform: when the same plan has no change
on a drifted resource, or an update touching none of the drifted attributes, the Finding is *acknowledged*
(severity info, own Markdown section, reason `ignore_changes` or `not_reverted`). If apply would revert any drifted
attribute, would recreate it after it was deleted outside Terraform, or replace it because of a drifted attribute, it stays Drift.
A delete or replace that comes from a code change (resource removed from code, replace by request or trigger) is not a
revert and is reported as Pending. This follows Terraform's own plan (defaults, `default_tags`, `dynamic` blocks), with no special cases per provider; the
path depth cap only widens overlap, never hides it. Because the drift plan is a normal plan, plan-time validation,
preconditions and unknown `count`/`for_each` can make a Root a Scan error that a refresh-only plan would have scanned;
the Pending plan runs only after it succeeds. See ADR-0011.

## Permissions

`plan -lock=false` needs read access to state and to every resource. For S3 state that is
`s3:ListBucket` and `s3:GetObject`; no lock or write permission. Use a dedicated read-only identity.

## Enabling workspaces

Adding a `workspaces:` rule for a directory renames its Roots from `path` to `path@name`. The first Scan after
that does not find the old Roots, so it resolves their Findings and reports the same Drift as new once.

## Unmanaged resource count - experimental

Not yet run against a real AWS Config recorder; flags and output may change.

`driftscan unmanaged` counts AWS resources that exist but that no state manages, per resource type. It is a number
to trend, not a list to fix (ADR-0010). It reads every Root's state read-only (same `-C` and `drift.yaml`, workspaces
included), lists resources with an AWS Config advanced query and matches by ARN (by id only when Config returns no ARN).

```
driftscan unmanaged -C infra -out unmanaged.json -examples 5 -otlp
driftscan unmanaged -C infra -aggregator org-aggregator -fail-over 50
```

- `-types` comma-separated Config types; default `AWS::EC2::Instance`, `AWS::EC2::SecurityGroup`, `AWS::S3::Bucket`,
  `AWS::IAM::Role`, `AWS::RDS::DBInstance`, `AWS::Lambda::Function`.
- `-out` JSON (per type: total, managed, unmanaged; `-examples N` adds up to N unmanaged ARNs, or resource ids when Config has no ARN), Markdown to
  `$GITHUB_STEP_SUMMARY`, `-otlp` gauge `driftscan.unmanaged{resource_type}`.
- Exit 0, 2 on error, 1 only with `-fail-over N` and a total above N.
- Needs the AWS Config recorder on for the types and `config:SelectResourceConfig` (or
  `config:SelectAggregateResourceConfig` with `-aggregator`); AWS credentials come from the default SDK chain.
- Expect noise: service-created resources, CloudFormation, default VPC and security groups.

## Not supported (yet)

- Roots using `terraform workspace` without a `workspaces:` rule: only the current workspace is planned.
- HCP Terraform remote execution (`cloud` block): skipped unless listed under `roots:` with local execution.
- Resources created outside Terraform are invisible to plan-based `scan`; `driftscan unmanaged` counts them (below).

## How it compares

| | driftscan | tfdrift | Digger / Terramate / Terrateam drift | HCP Terraform health |
|---|---|---|---|---|
| Separates Drift from Pending change | yes | no | no | no |
| Alerts only on change vs last run | yes (Baseline file) | partial | Terramate Cloud only | yes |
| Values in output | never | yes | plan output | yes |
| Install | static binary + provenance | pip at runtime | varies | SaaS |
| Remediation | no, by design | yes | yes | yes |

## License

Copyright 2026 Oleksandr Kolomiiets. Licensed under Apache-2.0.
