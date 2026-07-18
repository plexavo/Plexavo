"""Category 6: Encryption and Data Protection — checks 29-31, all Medium.

check_29 (EBS) and check_30 (RDS) are straightforward flag-checks, no
surprises expected.

check_31 (S3 default encryption) carries the SAME risk that broke
STOR-19's original "missing PAB" ground truth, flagged proactively this
time instead of discovered by a failed apply: AWS made SSE-S3 the
mandatory, automatic default for every S3 bucket in January 2023,
applied irrevocably (you can only upgrade to SSE-KMS, never disable
encryption entirely). A bucket created today will very likely ALWAYS
have at least a default AES256 configuration, meaning
ServerSideEncryptionConfigurationNotFoundError may be unreachable for
any bucket created post-January-2023. The check itself is still correct
and valuable — for real customer accounts with buckets that predate
this change and were never touched since — it's just probably not
something we can ground-truth with a freshly created bucket. We'll know
for certain once Terraform is applied; not assuming either way.

Confirmed via the real S3 service model before writing this (not
guessed): neither ServerSideEncryptionConfigurationNotFoundError here,
nor the two S3 error codes storage.py hit, are modeled as distinct
exception classes. Generic ClientError + error-code inspection used from
the start this time.
"""

from botocore.exceptions import ClientError

from plexavo.findings import Finding, Severity


def check_29_unencrypted_ebs_volumes(ec2) -> list[Finding]:
    """ENC-29: EBS volume with Encrypted=False."""
    findings = []
    paginator = ec2.get_paginator("describe_volumes")
    for page in paginator.paginate():
        for vol in page["Volumes"]:
            if vol.get("Encrypted"):
                continue
            vol_id = vol["VolumeId"]
            attachments = vol.get("Attachments", [])
            attached_to = (
                ", ".join(a["InstanceId"] for a in attachments)
                if attachments else "not attached to any instance"
            )
            findings.append(Finding(
                check_id="ENC-29",
                title="Unencrypted EBS Volume",
                severity=Severity.MEDIUM,
                resource_arn=vol_id,
                raw_detail=f"EBS volume '{vol_id}' ({attached_to}) is not encrypted. Data "
                           f"at rest on this volume — and any snapshot taken from it — is "
                           f"stored in plaintext.",
                account_context=f"attached_to={attached_to}",
            ))
    return findings


def check_30_unencrypted_rds_instances(rds) -> list[Finding]:
    """ENC-30: RDS instance with StorageEncrypted=False."""
    findings = []
    paginator = rds.get_paginator("describe_db_instances")
    for page in paginator.paginate():
        for db in page["DBInstances"]:
            if db.get("StorageEncrypted"):
                continue
            db_id = db["DBInstanceIdentifier"]
            engine = db.get("Engine", "unknown")
            findings.append(Finding(
                check_id="ENC-30",
                title="Unencrypted RDS Instance",
                severity=Severity.MEDIUM,
                resource_arn=db.get("DBInstanceArn", db_id),
                raw_detail=f"RDS instance '{db_id}' ({engine}) has StorageEncrypted=False. "
                           f"Data at rest — the database files, automated backups, and "
                           f"snapshots — is stored unencrypted.",
                account_context=f"engine={engine}",
            ))
    return findings


def check_31_s3_missing_default_encryption(s3, bucket_names: list) -> list[Finding]:
    """ENC-31: bucket has no default server-side encryption configuration.
    See module docstring on why this may rarely fire on modern buckets."""
    findings = []
    for name in bucket_names:
        try:
            s3.get_bucket_encryption(Bucket=name)
            continue  # has some encryption config, whatever it is
        except ClientError as e:
            if e.response["Error"]["Code"] != "ServerSideEncryptionConfigurationNotFoundError":
                raise
        findings.append(Finding(
            check_id="ENC-31",
            title="S3 Bucket Without Default Encryption",
            severity=Severity.MEDIUM,
            resource_arn=f"arn:aws:s3:::{name}",
            raw_detail=f"Bucket '{name}' has no default server-side encryption "
                       f"configuration. Objects uploaded without an explicit "
                       f"encryption header are stored in plaintext.",
            account_context=f"bucket={name}",
        ))
    return findings


def run_all(session) -> list[Finding]:
    """Run ENC-29 through ENC-31 against every relevant resource in the account."""
    ec2 = session.client("ec2")
    rds = session.client("rds")
    s3 = session.client("s3")
    bucket_names = [b["Name"] for b in s3.list_buckets()["Buckets"]]

    findings = []
    findings += check_29_unencrypted_ebs_volumes(ec2)
    findings += check_30_unencrypted_rds_instances(rds)
    findings += check_31_s3_missing_default_encryption(s3, bucket_names)
    return findings
