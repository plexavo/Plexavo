# IAM Hygiene Test Matrix — Checks 7-14

## Standard grading (via `plexavo scan`)

| Check | Terraform resource | Seeded condition | Must detect |
|---|---|---|---|
| IAM-07 | `hygiene07_wildcard_trust` | Trust policy `Principal: {AWS: "*"}` | High — Cross-Account Trust with Wildcard |
| IAM-08 | `hygiene08_external_trust` | Trust policy trusts account `111111111111` (a real, second AWS account) | High — Cross-Account Trust to External Account |
| IAM-11 | `hygiene_test_user` | 2 active access keys | High — Multiple Active Access Keys |
| IAM-12 | (your real account) | Real CloudTrail history — no synthetic positive case (see below) | **Nothing**, if root hasn't been used in the last 90 days. This is the expected, correct result — not an untested gap. |
| IAM-13 | (your real root account) | Real state — no synthetic case | Critical if root MFA is off, **nothing if it's on**. You already confirmed MFA status when you set up `lab-admin` — this should match what you know to be true. |
| IAM-14 | `risky_fn` / `clean_fn` | Admin execution role / least-privilege execution role | High on `risky_fn` only — `clean_fn` must produce nothing |

## IAM-12: same structural limitation as IAM-13, stated precisely

Only the negative case (no root usage → silent) can be validated against real account state. We will not log in as root to manufacture a positive test case — same reasoning as never disabling real root MFA. The check logic itself (server-side `Username=root` filter + client-side `userIdentity.type == "Root"` confirmation) is offline-verified, including the specific edge case of an IAM user literally named "root" NOT triggering a false positive.

## Threshold-parametrization grading (maintainer-only, not part of this repo)

IAM-09 and IAM-10 can't be graded through `plexavo scan` with real
90/180-day thresholds — `hygiene_test_user` and its keys are seconds old,
not 90 days old. The maintainer validates the comparison logic itself
separately, against threshold=0 and threshold=365 on a freshly-created
user, using a script that isn't part of this public repo (it's a
one-off calibration tool tied to live maintainer infrastructure, same
category as `terraform-testbed/` — see `docs/TEST-MATRIX.md`). If you're
contributing a change to this comparison logic, the offline tests in
`tests/test_iam_hygiene_offline.py` are what CI actually runs and what
your PR needs to pass — this section is a historical record of how the
*live* verification was originally done, not a script you need to
reproduce.

Expected result when that comparison logic is correct: threshold=0 fires
(age 0 >= 0), threshold=365 does not (age 0 < 365). This proves the
comparison logic is correct — it does not prove the real 90-day scenario,
because there isn't one to test against.

## Not covered by this round

None — with IAM-08 closed, all 14 IAM checks now have real ground truth (or the correctly-documented structural limitation for IAM-12/13).

## Setup

```bash
cd terraform-testbed
terraform apply
```
New in this apply: IAM-14's 2 Lambda functions (`iam-lambda-misconfigs.tf`, needs the `archive` provider — run `terraform init -upgrade` first if you haven't already). IAM-12 needs no new resources — it reads real CloudTrail history.

## Teardown

```bash
cd terraform-testbed
terraform destroy
```
