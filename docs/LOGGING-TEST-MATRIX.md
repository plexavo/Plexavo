# Logging Test Matrix — LOG-22 through LOG-25

## LOG-22 and LOG-23: now genuinely proven, not just offline-tested

Confirmed against a real, untouched second AWS account (`111111111111`, via `validate_log_gaps_second_account.py`): 0 trails found, both LOG-22 and LOG-23 fired exactly as predicted. This is the actual positive case, not an inference — the first time either check has been proven against real AWS data showing "no good trail exists," rather than only offline logic tests plus a confirmed negative case on the primary account.

The underlying reason this needed a second account still applies and hasn't changed: both checks are account-wide (`any(t["IsLogging"] for t in trails)`), so `lab-trail`'s existence in the primary account permanently satisfies both conditions there, regardless of what test trails exist alongside it. That's not a limitation anymore though — it's just the reason the proof had to happen somewhere else, and now it has.

**Re-testing this in the future requires repeating the account-B setup** (temporary IAM user, scoped inline policy, access key, `aws configure --profile`, run, then delete everything) — it's not a standing, repeatable part of this project's normal test cycle, by design. The one-off script used for this (`validate_log_gaps_second_account.py`) is **not** included in this public repo — it was written against a specific real account ID and a specific temporary IAM setup that no longer exist, and isn't useful without recreating both from scratch. This paragraph is the record of how it was proven, which is what actually needs to survive, not the script itself.

## LOG-24: closed with dedicated, isolated ground truth

Unlike 22/23, `check_24` evaluates **per-trail**, so a dedicated trail proves the negative case cleanly without ever touching `lab-trail` again — the mistake from the previous session (hand-editing a pre-existing key/trail's resource policies) isn't repeated here. `log_clean_trail` is a brand-new trail with its own bucket, its own KMS key, and correctly-configured resource policies for both, built together in one Terraform apply.

| Check | Resource | Condition | Must detect |
|---|---|---|---|
| LOG-24 (negative) | `log_clean_trail` | Multi-region, KMS-encrypted, logging | **Nothing** — proves a correctly-configured trail doesn't fire |
| LOG-24 (positive) | `lab-trail` (real) | No KMS key | Already confirmed in the prior session — unchanged |

## LOG-25: already fully confirmed, no new ground truth needed

Both directions already proven: fires correctly when GuardDuty has never been activated (`SubscriptionRequiredException` handling, confirmed against your real account), and the offline test confirms it stays silent when a detector exists.

## Setup

```bash
cd terraform-testbed
terraform apply
```

## Run

```bash
cd ..
plexavo scan --profile <your-testbed-profile>
```

Grade specifically: `log-clean-trail` should produce **zero** LOG-22/23/24 findings. `lab-trail` should still show LOG-24 only (unchanged from before), and LOG-22/23 should stay silent for the whole account — same as always, for the structural reason above, not because anything new was proven about those two checks.

## Teardown

```bash
cd terraform-testbed
terraform destroy
```
