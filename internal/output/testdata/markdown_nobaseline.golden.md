## driftscan

:red_circle: 3 Roots scanned, 2 with Drift.

**4 Drift** | 1 Pending changes | 1 Scan errors | 1 acknowledged | 0 resolved

_No Baseline: this Scan establishes it. Statuses start from the next Scan._

### Scan errors (1)

<details>
<summary><b>envs/dev/iam</b> - 1</summary>

| Severity | Status | Resource | Attributes | Location | Owner | Changed by |
|---|---|---|---|---|---|---|
| high | new | - | Error: no valid credential sources found | <code>envs/dev/iam/backend.tf:2</code> | - | - |

</details>

### Drift (4)

<details open>
<summary><b>envs/dev/network</b> - 3</summary>

| Severity | Status | Resource | Attributes | Location | Owner | Changed by |
|---|---|---|---|---|---|---|
| high | new (3 scans) | <code>aws_security_group.web</code> | <code>ingress&#91;0&#93;.cidr_blocks</code> | <code>envs/dev/network/sg.tf:12</code> | @org/sre | - |
| medium | new | <code>aws_vpc.main</code> | - | <code>envs/dev/network/vpc.tf:1</code> | - | - |
| low | new | <code>aws_route53_record.r&#91;&quot;a&#124;b&lt;c&#96;d&amp;e&quot;&#93;</code> | <code>ttl</code> | <code>envs/dev/network/dns (old).tf:7</code> | @org/sre | alice |

</details>

<details open>
<summary><b>envs/dev/data</b> - 1</summary>

| Severity | Status | Resource | Attributes | Location | Owner | Changed by |
|---|---|---|---|---|---|---|
| medium | new (2 scans) | <code>aws_s3_bucket.logs</code> | <code>versioning&#91;0&#93;.enabled, tags.Team</code> | <code>envs/dev/data/s3.tf:30</code> | @org/data | - |

</details>

### Pending changes (1)

<details>
<summary><b>envs/dev/data</b> - 1</summary>

| Severity | Status | Resource | Attributes | Location | Owner | Changed by |
|---|---|---|---|---|---|---|
| info | new | <code>aws_db_instance.main</code> | <code>allocated_storage</code> | <code>envs/dev/data/rds.tf</code> | - | - |

</details>

<details>
<summary><b>Acknowledged (1)</b></summary>

<details>
<summary><b>envs/dev/data</b> - 1</summary>

| Severity | Status | Resource | Attributes | Location | Reason | Owner | Changed by |
|---|---|---|---|---|---|---|---|
| info | new | <code>aws_s3_bucket.assets</code> | <code>tags.Name</code> | <code>envs/dev/data/s3.tf:5</code> | covered by lifecycle.ignore_changes | - | - |

</details>

</details>

