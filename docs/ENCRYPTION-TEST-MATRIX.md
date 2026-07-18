# Encryption Test Matrix — ENC-29 through ENC-31

## Grading (via `plexavo scan`)

| Check | Terraform resource | Seeded condition | Must detect |
|---|---|---|---|
| ENC-29 | `enc29_unencrypted` | EBS volume, `encrypted = false` | Medium — Unencrypted EBS Volume |
| ENC-CLEAN-ebs | `enc_clean_ebs` | EBS volume, `encrypted = true` | **Nothing** |
| ENC-31-test | `enc31_test` | Plain S3 bucket, no explicit encryption config | **Nothing — and that's the correct, expected result, not a gap.** AWS applies SSE-S3 by default automatically since Jan 2023; there's no way to create a bucket without it. If this bucket somehow DOES produce an ENC-31 finding, that's the actual anomaly worth investigating. |

## ENC-30 (RDS) — now has full ground truth

`net04_public_open` (unencrypted, from NET-04's testbed) proves the positive case. `enc_clean_rds` (new, `storage_encrypted = true`) proves the negative case. Both AWS-verified once this applies cleanly.

## A real, proactively-flagged risk for ENC-29

Some AWS accounts/regions have "EBS encryption by default" turned on — an account-level setting that, when enabled, forces every new EBS volume to be encrypted regardless of what's requested, similar in spirit to the S3 defaults that broke earlier ground truth. If `enc29_unencrypted` doesn't fire, this is very likely why. Check it directly:

```powershell
aws ec2 get-ebs-encryption-by-default --region us-east-1
```

If `true`, ENC-29's positive case needs redesigning (same pattern as STOR-19). Not assuming either way — the scan output tells us directly.

## Setup

```bash
cd terraform-testbed
terraform apply
```
3 new resources: 2 EBS volumes (fast — seconds, not the RDS wait) + 1 S3 bucket.

## Run

```bash
cd ..
plexavo scan --profile <your-testbed-profile>
```

## Teardown

```bash
cd terraform-testbed
terraform destroy
```
