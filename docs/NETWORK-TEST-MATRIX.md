# Network Test Matrix — NET-01 through NET-04

Same grading discipline as `TEST-MATRIX.md`: every row should appear
exactly once; every `NET-CLEAN-*` row should appear zero times.

| Test | Terraform resource | Seeded condition | Must detect |
|---|---|---|---|
| NET-01 | `net01_ssh_open` | SSH (22) open to 0.0.0.0/0, public IP | Critical — Admin Port Open |
| NET-02 | `net02_db_open` | MySQL (3306) open to 0.0.0.0/0, public IP | Critical — Database Port Open |
| NET-03 | `net03_all_open` | All ports/protocols open to 0.0.0.0/0, public IP | Critical — All Ports Open. **Also expect NET-01 and NET-02 to fire on the same instance** — stacking is intentional, not a bug (see network.py docstring). |
| NET-CLEAN-private | `net_private_canary` | Same SSH-open SG as NET-01, but **no public IP** | **Nothing.** Not exploitable without a public IP regardless of the SG rule. |
| NET-CLEAN-orphan | `net_orphan` (SG only, no instance) | SSH open to 0.0.0.0/0, attached to nothing | **Nothing.** An orphaned SG isn't exploitable. |
| NET-CLEAN-scoped | `net_office_only` | SSH scoped to `203.0.113.0/24` (not 0.0.0.0/0), public IP | **Nothing.** Not open to the internet. |
| NET-CLEAN-https | `net_clean_https` | HTTPS (443) open to 0.0.0.0/0, public IP | **Nothing.** Not an admin port, not a DB port, not all-ports — legitimate public web server pattern. |
| NET-04 | `net04_public_open` (RDS) | `PubliclyAccessible=true`, SG opens 3306 to 0.0.0.0/0 | Critical — Publicly Accessible Database |
| NET-CLEAN-rds-locked-sg | `net04_clean_locked_sg` (RDS) | `PubliclyAccessible=true`, but SG only allows 3306 from `10.0.0.0/8` | **Nothing.** PubliclyAccessible alone isn't sufficient — the SG must actually expose the port. |
| NET-CLEAN-rds-not-public | `net04_clean_not_public` (RDS) | `PubliclyAccessible=false`, using the **exact same wide-open SG** as `net04_public_open` | **Nothing.** PubliclyAccessible is the authoritative gate — an open SG alone doesn't matter if there's no public endpoint. |

## Setup

```bash
cd terraform-testbed
terraform apply
```

This also recreates the IAM testbed resources (already validated — harmless, just confirms nothing regressed). New in this apply: 6 EC2 instances + security groups, 3 RDS instances (db.t3.micro) + subnet group, and the scanner role's EC2/RDS describe permissions. **RDS takes 5-10 minutes to provision** — the EC2 instances and IAM resources will finish first; wait for `Apply complete` before scanning.

Get resource IDs for grading:
```bash
terraform output network_test_instance_ids
terraform output rds_test_instance_ids
```

## Run

```bash
cd ..
plexavo scan --profile <your-testbed-profile>
```

## Grading

For each row: confirm the check ID fired on the correct instance ID, correct severity, and that the `raw_detail` correctly names the port/service. Confirm every `NET-CLEAN-*` instance produces zero findings.

## Teardown

```bash
cd terraform-testbed
terraform destroy
```
6 running EC2 instances + 3 running RDS instances — don't leave this stack up longer than the grading pass needs. RDS destroy also takes 5-10 minutes; the command will finish once AWS confirms deletion, not immediately.

## What's NOT covered yet

ELB/ALB public exposure, Lambda function URLs, API Gateway public endpoints, NACLs. Category 2 in the blueprint may define more checks than these 4 — this covers the highest-signal single-resource ones first, same "ground truth first, breadth later" approach as IAM.
