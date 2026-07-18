# Storage Test Matrix — STOR-19 through STOR-21

## Account-level BPA diagnostic — result confirmed

```
NoSuchPublicAccessBlockConfiguration: The public access block configuration was not found
```

No account-level restriction exists. STOR-20/21 ground truth is safe and now built below — no trade-off, no temporary setting change needed.

## Grading (via `plexavo scan`)

| Check | Terraform resource | Seeded condition | Must detect |
|---|---|---|---|
| STOR-19-missing | `stor19_missing_pab` | All 4 PAB settings explicitly disabled (redesigned — see note below) | Critical — names all 4 settings as disabled |
| STOR-19-partial | `stor19_partial_pab` | PAB present, `BlockPublicPolicy` disabled | Critical — names specifically "BlockPublicPolicy" as the disabled setting |
| STOR-20 | `stor20_public_policy` | Bucket policy grants `Principal:*`, `s3:GetObject` | Critical — Bucket Policy Allows Public Access. **Also expect STOR-19 to fire on this same bucket** — its PAB override is only partial, same intentional stacking as NET-03/NET-01/02. |
| STOR-21 | `stor21_public_acl` | ACL grants `READ` to the AllUsers group | Critical — Bucket ACL Grants Public Access. **Also expect STOR-19 to fire here too**, same reason. |
| STOR-CLEAN | `stor_clean` | Full PAB (all 4 true), no policy, no public ACL | **Nothing**, across all three checks (19, 20, 21) |

## A real limitation, not a gap we're hiding

`STOR-19-missing`'s original design — a bucket with literally no `PublicAccessBlock` record — turned out to be impossible to manufacture with a bucket created today. AWS changed the default in April 2023: every newly-created bucket now automatically gets a PublicAccessBlock record (all 4 settings `true`), regardless of whether Terraform explicitly configures one. We confirmed this empirically: the code path meant to catch "no record exists" (`NoSuchPublicAccessBlockConfiguration`) never actually triggered on any freshly-created bucket. The bucket now explicitly sets all 4 settings to `false` instead, which tests the same real-world risk (a fully unprotected bucket) — but the specific "record doesn't exist at all" branch in `check_19` is only exercised in practice by buckets that predate April 2023. That code is still correct (older AWS accounts genuinely have buckets like this), it's just not something we can currently prove with a fresh Terraform apply.

## Setup

```bash
cd terraform-testbed
terraform apply
```
11 new resources: 3 test buckets + clean bucket + PAB configs + ownership controls + ACL + policy + a random suffix for globally-unique bucket names.

## Run

```bash
cd ..
plexavo scan --profile <your-testbed-profile>
```

## A real-account caveat, same as `lab-admin` before

`storage.py` scans **every bucket in your account**, not just the testbed ones — that's correct, required behavior for a real scan. If you have any pre-existing buckets from other projects, expect findings on those too. That's not noise, it's the tool doing its job; review them the same way you reviewed `lab-admin`'s access keys.

## Teardown

```bash
cd terraform-testbed
terraform destroy
```
