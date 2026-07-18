"""Category 3: Storage Exposure — checks 19-21, all Critical.

Scope note: check_19 checks BUCKET-level PublicAccessBlock only, per the
blueprint's literal spec (GetBucketPublicAccessBlock). It does NOT check
ACCOUNT-level S3 Block Public Access (a separate API, s3control's
GetPublicAccessBlock) — AWS enforces the more restrictive of the two, so
a bucket could show as unprotected here while actually still being safe
due to an account-level setting this check doesn't see. Stated limitation,
not an oversight — same "don't overclaim" pattern as every other check.
"""

import json

from botocore.exceptions import ClientError

from plexavo.findings import Finding, Severity
from plexavo.principals import _normalize

PUBLIC_GROUP_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers": "AllUsers (anyone on the internet, no AWS account needed)",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers": "AuthenticatedUsers (any AWS account holder, not just yours)",
}

PAB_SETTINGS = ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]


def list_buckets(s3) -> list:
    return [b["Name"] for b in s3.list_buckets()["Buckets"]]


def check_19_missing_public_access_block(s3, bucket_names: list) -> list[Finding]:
    """STOR-19: bucket-level PublicAccessBlock missing entirely, or present
    but with any of the 4 settings disabled.

    Uses generic ClientError + error-code inspection, NOT
    s3.exceptions.NoSuchPublicAccessBlockConfiguration — confirmed against
    the real S3 service model that this error code is not modeled as a
    distinct exception shape (unlike, say, IAM's NoSuchEntityException),
    so the dynamic-exception-class pattern silently never matches and the
    code never raises AttributeError only because it's also never
    triggered — a latent bug, not a working code path, until this fix."""
    findings = []
    for name in bucket_names:
        try:
            config = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            off = [s for s in PAB_SETTINGS if not config.get(s, False)]
            if not off:
                continue
            detail = (f"has PublicAccessBlock configured, but "
                      f"{', '.join(off)} {'is' if len(off) == 1 else 'are'} disabled")
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
                raise
            detail = "has NO PublicAccessBlock configuration at all — none of the four protections are in place"
        findings.append(Finding(
            check_id="STOR-19",
            title="S3 Bucket Missing PublicAccessBlock Protection",
            severity=Severity.CRITICAL,
            resource_arn=f"arn:aws:s3:::{name}",
            raw_detail=f"Bucket '{name}' {detail}. All four settings should be enabled "
                       f"unless there's a specific, documented reason not to.",
            account_context=f"bucket={name}",
        ))
    return findings


def check_20_public_bucket_policy(s3, bucket_names: list) -> list[Finding]:
    """STOR-20: bucket policy grants Allow to Principal:* (or {"AWS":"*"}).
    Same ClientError pattern as check_19, same real reason — confirmed
    NoSuchBucketPolicy isn't modeled as a distinct S3 exception either."""
    findings = []
    for name in bucket_names:
        try:
            policy_str = s3.get_bucket_policy(Bucket=name)["Policy"]
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
                raise
            continue
        policy = json.loads(policy_str)
        for stmt in policy.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal")
            is_public = principal == "*" or (
                isinstance(principal, dict) and "*" in _normalize(principal.get("AWS"))
            )
            if not is_public:
                continue
            actions = _normalize(stmt.get("Action"))
            findings.append(Finding(
                check_id="STOR-20",
                title="S3 Bucket Policy Allows Public Access",
                severity=Severity.CRITICAL,
                resource_arn=f"arn:aws:s3:::{name}",
                raw_detail=f"Bucket '{name}' has a bucket policy statement granting "
                           f"{', '.join(actions)} to Principal:* — anyone on the internet, "
                           f"no AWS account required, can perform these actions.",
                account_context=f"bucket={name}",
            ))
    return findings


def check_21_public_acl(s3, bucket_names: list) -> list[Finding]:
    """STOR-21: bucket ACL grants any permission to the AllUsers or
    AuthenticatedUsers built-in groups."""
    findings = []
    for name in bucket_names:
        acl = s3.get_bucket_acl(Bucket=name)
        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            if grantee.get("Type") != "Group":
                continue
            label = PUBLIC_GROUP_URIS.get(grantee.get("URI"))
            if not label:
                continue
            permission = grant.get("Permission")
            findings.append(Finding(
                check_id="STOR-21",
                title="S3 Bucket ACL Grants Public Access",
                severity=Severity.CRITICAL,
                resource_arn=f"arn:aws:s3:::{name}",
                raw_detail=f"Bucket '{name}' ACL grants {permission} to {label}. S3 ACLs "
                           f"are a legacy access-control mechanism — this is rarely "
                           f"intentional and should be reviewed immediately.",
                account_context=f"bucket={name}, permission={permission}",
            ))
    return findings


def run_all(session) -> list[Finding]:
    """Run STOR-19 through STOR-21 against every bucket in the account —
    not just testbed buckets. A real scan must check everything."""
    s3 = session.client("s3")
    bucket_names = list_buckets(s3)
    findings = []
    findings += check_19_missing_public_access_block(s3, bucket_names)
    findings += check_20_public_bucket_policy(s3, bucket_names)
    findings += check_21_public_acl(s3, bucket_names)
    return findings
