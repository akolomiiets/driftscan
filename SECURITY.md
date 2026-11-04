# Security policy

## Supported versions

Only the latest minor release receives security fixes. Please upgrade before reporting an issue against an older one.

## Reporting a vulnerability

Do not open a public issue. Use GitHub private vulnerability reporting: open the repository's Security tab and choose
"Report a vulnerability", or go directly to
https://github.com/akolomiiets/driftscan/security/advisories/new.

This is a personal project: responses are best effort, with no guaranteed timeline.

## Scope

In scope:

- The `driftscan` CLI.
- The composite GitHub Action (`action.yml`).
- Release artifacts (binaries, `checksums.txt`, build provenance attestations).

Attribute values from Terraform state or plans must never reach any output (ADR-0002). A leak of an attribute value
into the console, JSON, HTML, Markdown, Slack or OTLP output is a security bug; please report it as one.

Out of scope: vulnerabilities in Terraform, OpenTofu, providers or other third-party tools driftscan invokes.
