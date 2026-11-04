# Enrich resolves identifiers itself

CloudTrail is queried by resource id or ARN, but a Report carries no attribute values (ADR-0002), and ids are values. So `driftscan enrich -cloudtrail` does not read them from the Report: for each Root with AWS Drift Findings it runs `terraform show -json` on the current state, reads only `id` and `arn` of the drifted addresses in memory, looks them up in CloudTrail and keeps only the actor, time and event name on the Finding. Ids and ARNs are never written to the Report, logs or warnings.

## Consequences

- The Report stays value-free and ADR-0002 is unchanged; a raw Report can still be shared and stored freely.
- The cost moves to `enrich`: it needs the same state read access and terraform binary as `scan`, plus `cloudtrail:LookupEvents`, and it re-inits every drifted Root (slower than a pure Report transform).
- It runs in the job that has credentials, not wherever the Report ends up; `scan` and `report` still import no cloud SDK (ADR-0007).
