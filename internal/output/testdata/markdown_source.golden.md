## driftscan

:red_circle: 3 Roots scanned, 2 with Drift.

**3 Drift** | 1 Pending changes | 1 Scan errors | 1 acknowledged | 1 resolved

Active Findings: 3 new, 1 changed.

### Scan errors (1)

<details>
<summary><b>envs/dev/iam</b> - 1</summary>

| Severity | Status | Resource | Attributes | Location | Owner | Changed by |
|---|---|---|---|---|---|---|
| high | new | - | Error: no valid credential sources found | [infra/envs/dev/iam/backend.tf:2](https://github.com/acme/infra-repo/blob/abc123/infra/envs/dev/iam/backend.tf#L2) | - | - |

</details>

### Drift (3)

<details open>
<summary><b>envs/dev/data</b> - 1</summary>

| Severity | Status | Resource | Attributes | Location | Owner | Changed by |
|---|---|---|---|---|---|---|
| medium | changed (2 scans) | <code>aws_s3_bucket.logs</code> | <code>versioning&#91;0&#93;.enabled, tags.Team</code> | [infra/envs/dev/data/s3.tf:30](https://github.com/acme/infra-repo/blob/abc123/infra/envs/dev/data/s3.tf#L30) | @org/data | - |

</details>

<details open>
<summary><b>envs/dev/network</b> - 2</summary>

| Severity | Status | Resource | Attributes | Location | Owner | Changed by |
|---|---|---|---|---|---|---|
| low | new | <code>aws_route53_record.r&#91;&quot;a&#124;b&lt;c&#96;d&amp;e&quot;&#93;</code> | <code>ttl</code> | [infra/envs/dev/network/dns (old).tf:7](https://github.com/acme/infra-repo/blob/abc123/infra/envs/dev/network/dns%20%28old%29.tf#L7) | @org/sre | alice |
| high | persisting (3 scans) | <code>aws_security_group.web</code> | <code>ingress&#91;0&#93;.cidr_blocks</code> | [infra/envs/dev/network/sg.tf:12](https://github.com/acme/infra-repo/blob/abc123/infra/envs/dev/network/sg.tf#L12) | @org/sre | - |

</details>

### Pending changes (1)

<details>
<summary><b>envs/dev/data</b> - 1</summary>

| Severity | Status | Resource | Attributes | Location | Owner | Changed by |
|---|---|---|---|---|---|---|
| info | new | <code>aws_db_instance.main</code> | <code>allocated_storage</code> | [infra/envs/dev/data/rds.tf](https://github.com/acme/infra-repo/blob/abc123/infra/envs/dev/data/rds.tf) | - | - |

</details>

### Resolved since last Scan (1)

<details>
<summary><b>envs/dev/network</b> - 1</summary>

| Severity | Status | Resource | Attributes | Location | Owner | Changed by |
|---|---|---|---|---|---|---|
| medium | resolved | <code>aws_vpc.main</code> | - | [infra/envs/dev/network/vpc.tf:1](https://github.com/acme/infra-repo/blob/abc123/infra/envs/dev/network/vpc.tf#L1) | - | - |

</details>

<details>
<summary><b>Acknowledged (1)</b></summary>

<details>
<summary><b>envs/dev/data</b> - 1</summary>

| Severity | Status | Resource | Attributes | Location | Reason | Owner | Changed by |
|---|---|---|---|---|---|---|---|
| info | new | <code>aws_s3_bucket.assets</code> | <code>tags.Name</code> | [infra/envs/dev/data/s3.tf:5](https://github.com/acme/infra-repo/blob/abc123/infra/envs/dev/data/s3.tf#L5) | covered by lifecycle.ignore_changes | - | - |

</details>

</details>

