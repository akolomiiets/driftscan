# driftscan playground (moto)

A local sandbox to see how driftscan reports many different shapes of drift. It runs real Terraform with the
real AWS provider against [moto](https://github.com/getmoto/moto) (an AWS emulator, image
`motoserver/moto:5.2.5`) in Docker. No AWS account, credentials or network access to AWS are involved.

## Prerequisites

Docker with Compose v2, Terraform 1.5 or newer, the AWS CLI v2 (used only to make changes outside Terraform), Go
(to build driftscan from this repo), `make` and `bash`. The first `terraform init` downloads the AWS provider
(pinned to 5.100.0) once into `.tfcache/`; moto listens on `127.0.0.1:5555`.

## Run it

Run from this directory.

```sh
make up        # start moto and wait until healthy
make apply     # terraform init + apply in every Root (the scan-error Root is left alone)
make scan      # first Scan: builds driftscan, writes baseline.json, report.html, summary.md
make break     # change things outside Terraform with the aws CLI (scripts/break.sh)
make rescan    # second Scan: new findings, acknowledged drift, statuses against the Baseline
make pending   # edit the code of one Root without applying it
make rescan    # a Pending change appears; everything else is "persisting"
make fix       # terraform apply again in every Root
make rescan    # most findings become "resolved"
make down      # stop moto, delete state, reports and the Baseline
```

Open `report.html` in a browser after any scan (the environment map has a `dev` and a `prod` row). `summary.md`
is the Markdown summary and the GitHub Actions annotations are printed to the terminal (`-annotations on`).
The Baseline is `baseline.json`; each scan reads it and writes it back, as in the GitHub Actions example in the
main README. `-fail-on none` keeps the exit code at 0.

## Layout

`envs/dev/<root>` and `envs/prod/<root>` are ordinary Terraform Roots with a local backend (the state file sits
in the Root and is git-ignored). `providers.tf` is identical in every Root (copy of `shared/providers.tf.txt`):
it points the AWS provider at moto with dummy credentials. Resource names say which shape they demonstrate.
Every resource carries an explicit `tags` map: moto reports empty tag maps in a way that would otherwise add
noise to untouched resources.

## Shapes and what was observed

Observed with `make up`, `apply`, `scan`, `break`, `rescan` (moto 5.2.5, AWS provider 5.100.0). Severity comes from
the built-in rules (for example IAM and policies are high, tags are info).

| # | Shape | Root / resource | What `break` does | Observed on the rescan |
|---|---|---|---|---|
| 1 | Simple scalar attribute | `dev/scalar-and-tags`: `scalar_attribute_drift` (SQS), `scalar_description_drift` (SSM) | visibility timeout 30 to 60; SSM description edited | Drift, medium: `visibility_timeout_seconds`; `description, version` (the SSM version bumps on every write) |
| 2 | Map attribute | `dev/scalar-and-tags`: `map_tags_drift` | one tag changed, one added, one removed | Drift, info: `tags.changed, tags.added_outside, tags.to_remove` and the same under `tags_all.*` |
| 3 | Set of nested blocks | `dev/sg-inline-set`: `inline_ingress_set_drift` | the ssh rule is replaced (revoke + authorize with another CIDR) | Drift, high: `ingress[0..2].*` for every rule, not only the changed one (see below) |
| 3b | Set of nested blocks (DB parameter group) | `dev/db-parameter-group-set`: `parameter_set_drift` | `modify-db-parameter-group` changes `max_connections` and one apply method | Drift, medium: `parameter[0]` to `parameter[4]`. See the moto limitation below: this Root is drifted even before `break` |
| 4 | Rules in separate resources | `dev/sg-separate-rules`: `separate_rules_not_reverted` | adds a port 8080 rule that Terraform does not know | Drift, info, acknowledged `not_reverted`: `ingress[0], ingress[1]` |
| 5a | IAM role with separate inline policy | `dev/iam-role-policies`: `extra_inline_policy_not_reverted` | adds an inline policy | Drift, info, acknowledged `not_reverted`: `inline_policy[0], inline_policy[1]` |
| 5b | IAM `assume_role_policy` | `dev/iam-role-policies`: `assume_role_policy_drift` | trust policy changed to another service | Drift, high: `assume_role_policy, inline_policy[0]` (the inline policy is listed because the role is one resource; not marked acknowledged because the update is a real revert) |
| 6 | S3 settings as separate resources | `dev/s3-separate-resources`: `versioning_changed_outside`, `policy_changed_outside`, bucket | versioning suspended, bucket policy replaced | Drift on `aws_s3_bucket_versioning` (medium, `versioning_configuration[0].status`) and `aws_s3_bucket_policy` (high, `policy`); the bucket itself is acknowledged `not_reverted` (`policy`) |
| 7 | `lifecycle.ignore_changes` | `dev/ignore-changes` | visibility timeout 30 to 90 | Drift, info, acknowledged `ignore_changes`: `visibility_timeout_seconds` |
| 8 | `for_each` keys with special characters | `dev/for-each-odd-keys` | visibility timeout changed on all four queues | Drift, medium, one Finding per key: `odd_key["a\|b"]`, `["x<y"]`, `["dots.and spaces"]`, `["quote\"d"]`. They appear escaped in the Markdown table and in `report.html`, and raw in the annotation titles |
| 9 | Deleted outside Terraform | `dev/deleted-outside` | `delete-queue` | Drift, medium, action `delete` (apply would create it again) |
| 10 | Pending change | `dev/pending-change` | nothing outside; `make pending` adds `pending_override.tf` (a variable default changes, not applied) | Pending, info: `message_retention_seconds`. Not Drift |
| 11 | Scan error | `dev/scan-error` | never applied | Scan error, high: `plan: Error: No value for required variable`; stays after every scan and is never marked resolved |
| 12 | Clean Root | `dev/clean`, `prod/clean` | nothing | no Finding |
| - | Second environment | `prod/scalar-and-tags`, `prod/iam-role-policies`, `prod/clean` | queue visibility changed, inline policy added | Drift on the queue; the role is acknowledged `not_reverted` (gives the HTML map a `prod` row) |

### Why many `ingress[N]` / `parameter[N]` paths show up

Inline `ingress` blocks of a security group and `parameter` blocks of a DB parameter group are Terraform *sets*.
A set has no stable order, so driftscan sees them as positional elements (`ingress[0]`, `ingress[1]`, ...). When
one element changes, the set is re-sorted and the elements after it shift positions, so Terraform's diff compares
the old element N with a different new element N and reports `name`, `value`, `apply_method` (or `cidr_blocks`,
`from_port`, ...) as drifted for every shifted index, not only for the rule you touched. Read the paths as "something
in this set changed", then look at the plan or the console for the exact element. Only paths are reported, never
values.

### Things that behave differently on moto (observed)

- **DB parameter group.** moto does not return the source of a parameter, so the AWS provider reads back an empty
  parameter set. The Root is therefore Drift (`parameter[0]` to `parameter[4]`) right after `apply`, before `break`, it
  does not change when `break` runs, and it stays drifted after `make fix`. On real AWS only the changed elements
  would show up. It is kept to show the positional set paths.
- **Acknowledged drift before `break`.** Roles with inline policies, the S3 bucket and the security group with a
  separate rule are listed as acknowledged `not_reverted` on the very first Scan: the provider reads the separately
  managed policies and rules back into the parent resource's attributes (`inline_policy`, `ingress`, `policy`) and
  the plan shows them as changed without any outside change. This is the same acknowledgement mechanism as in
  shapes 4 to 6, just triggered without an outside change.
- **After `make fix`** every Finding except the DB parameter group and one S3 bucket attribute
  (`versioning[0].enabled`, acknowledged) is `resolved`, including the acknowledged ones. A `terraform apply` writes
  the refreshed state, so an outside change that apply does not revert (the extra security group rule, the extra
  inline policy) is absorbed into the state and no longer shows as a change, even though it still exists in moto.
- Acknowledged Findings are never annotated, so they appear only in `summary.md` and `report.html`.
