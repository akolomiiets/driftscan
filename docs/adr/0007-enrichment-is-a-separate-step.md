# Enrichment is a separate step

Knowing who changed a resource (CloudTrail) or who owns a Root (CODEOWNERS, git history) makes a Finding actionable, but it is cloud-specific and needs extra permissions. So it lives in `driftscan enrich`, which reads a Report and adds actor and owner fields; `scan` and `report` never import a cloud SDK. Only the job that runs `enrich` needs `cloudtrail:LookupEvents`.

## Consequences

- Phases: v1 is the core (scan, report, outputs, noise controls); v1.1 adds `enrich`; v2 adds an unmanaged-resource count from AWS Config and the AI advisor, each with its own ADR because both widen what the tool reads.
