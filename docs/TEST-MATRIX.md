# Day 1 Test Matrix — IAM Checks 1-6

Grade the scanner's output against this table. Every row should appear
exactly once in the report; CLEAN should appear zero times.

| Check ID | Terraform resource | Seeded misconfig | Must detect |
|---|---|---|---|
| IAM-01 | `check01_wildcard_admin` | `Action:*, Resource:*` inline policy | Critical — Wildcard Admin |
| IAM-02 | `check02_self_escalation` | `iam:PutRolePolicy`/`AttachRolePolicy` on `Resource:*` | Critical — Self-Escalation |
| IAM-03 | `check03_attacker` | `iam:CreatePolicyVersion` on a policy owned by `check03_policy_owner`, not itself | Critical — CreatePolicyVersion |
| IAM-04 | `check04_attacker` | `iam:PassRole` (scoped to `check04_target_admin`) + `ec2:RunInstances`; target role trusts `ec2.amazonaws.com` and has `AdministratorAccess` | Critical — PassRole+Compute |
| IAM-05 | `check05_attacker` | `sts:AssumeRole` scoped to `check05_target_admin`, which has `AdministratorAccess` | Critical — AssumeRole Chain to Admin |
| IAM-06 | `check06_wildcard_assumerole` | `sts:AssumeRole` on `Resource:*` | Critical — Wildcard AssumeRole |
| CLEAN | `clean_least_privilege` | `s3:GetObject`/`ListBucket` scoped to one bucket only | **Nothing.** Any finding here is a false positive — a bug. |
| GROUP-TEST | `group_test_member` (user) + `group_test_admins` (group) | Wildcard admin via group policy — **zero direct/inline policies on the user itself** | Critical — IAM-01, on the user, sourced entirely from the group. Validates `list_groups_for_user()` actually works against real AWS, not just against hand-built test data. |
| DENY-TEST | `deny_test_breakglass` | `AdministratorAccess` attached + inline `Deny:*/*` (break-glass pattern) | **Nothing.** The Deny fully overrides the Allow. Any finding here means Deny-evaluation is broken. |
| BOUNDARY-TEST | `boundary_test_attacker` → `boundary_test_capped_admin` | Same PassRole+compute shape as check04, but the target role has `AdministratorAccess` capped by a **narrow, non-wildcard permission boundary** | **Nothing.** The boundary caps the target below admin-equivalent, so it must not qualify as an IAM-04 escalation target. Any IAM-04 finding naming `boundary-test-capped-admin` as the target is a bug. |
| HEURISTIC-TEST | `heuristic_attacker` → `heuristic_admin_target` | Target's policy grants `iam:*`, `ec2:*`, `s3:*` **individually — no literal `"*"` anywhere** | Critical — IAM-04, naming `heuristic-admin-target` as the target. Validates the second, previously-untested branch of `is_admin_equivalent()` (the non-literal-wildcard heuristic), not just the literal-`Action:*` path every other test case uses. |

Expected `terraform plan` count is now **39 to add** (35 + 4 new heuristic-test resources).

## Setup

**Note:** `terraform-testbed/` is intentionally not part of this repo — it's
the maintainer's own live-AWS validation infrastructure, not something a
contributor needs to run the scanner or its test suite. The offline tests
in `tests/` (fake AWS API responses, zero live calls) are what actually
validate check logic today, and what CI runs. This matrix documents what
the maintainer verified against a live account before merging; it's a
record, not a script you can run without recreating that infrastructure
yourself.

If you do have your own equivalent test infrastructure:

```bash
cd terraform-testbed
terraform init
terraform apply    # review the plan first

# Grab the profile/region you configured for this AWS account
aws configure list-profiles
```

## Run the scan

```bash
pip install -e ".[dev]"
plexavo scan --profile <your-testbed-profile>
```

## Grading

For each row above, confirm:
1. The check ID fired on the correct resource ARN (not a different test role).
2. The severity matches.
3. `raw_detail` correctly names the specific permission and — for IAM-04/05 — correctly names the target admin role. Wrong attack narrative here is worse than a missed finding; it's the exact thing that erodes trust with a technical reviewer.
4. CLEAN produced nothing.

## Teardown

```bash
cd terraform-testbed
terraform destroy
```

Don't leave this stack up — `AdministratorAccess` is genuinely attached to
two roles in your account for the duration of this test. Destroy it the
same session you validate it, same discipline as the offensive lab.

## What's NOT covered yet

Checks 7-14 (cross-account trust, dormant users, access key age, root MFA,
Lambda admin roles) need real time-decay data or touch your actual root
account — those get their own ground-truth pass next, separate from this
Terraform stack.
