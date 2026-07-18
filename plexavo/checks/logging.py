"""Category 4: Logging and Detection — checks 22-25, all High.

Real-account note: this project's own AWS account already has a real
CloudTrail trail (revealed by the aws-cloudtrail-logs-... bucket that
surfaced in an earlier scan) — checks 22/23/24 have a genuine,
no-setup-needed validation opportunity against real account state, same
pattern as IAM-13's root MFA check.

Confirmed against the real botocore service models before writing this,
not guessed:
- DescribeTrails already includes IsMultiRegionTrail and KmsKeyId per
  trail — no separate GetTrail call needed for those two fields.
- IsLogging is ONLY available via GetTrailStatus (per-trail), not
  DescribeTrails — a trail can exist and still be stopped.
- ListDetectors returns an empty list, not an exception, when GuardDuty
  isn't enabled — simpler than the S3 "NotFound" exception pattern from
  storage.py/encryption.py.

IsLogging is fetched once per trail in run_all() and shared across
checks 22/23/24, rather than each check independently re-calling
GetTrailStatus for the same trail three times.
"""

from botocore.exceptions import ClientError

from plexavo.findings import Finding, Severity


def _trails_with_status(cloudtrail) -> list:
    """All trails, each enriched with its real-time IsLogging status."""
    trails = cloudtrail.describe_trails()["trailList"]
    enriched = []
    for trail in trails:
        status = cloudtrail.get_trail_status(Name=trail["TrailARN"])
        enriched.append({**trail, "IsLogging": status.get("IsLogging", False)})
    return enriched


def check_22_cloudtrail_not_enabled(trails: list) -> list[Finding]:
    """LOG-22: no trail is actively logging. A trail can exist and still
    be stopped — 'exists' alone doesn't mean 'enabled'."""
    if any(t["IsLogging"] for t in trails):
        return []
    return [Finding(
        check_id="LOG-22",
        title="CloudTrail Not Enabled",
        severity=Severity.HIGH,
        resource_arn="account",
        raw_detail="No CloudTrail trail is actively logging in this account "
                   "(either no trail exists, or every existing trail is "
                   "stopped). There is no audit trail of API activity — if "
                   "something happens, there is no way to reconstruct what.",
        account_context="cloudtrail",
    )]


def check_23_cloudtrail_not_all_regions(trails: list) -> list[Finding]:
    """LOG-23: no actively-logging trail covers all regions."""
    if any(t["IsLogging"] and t.get("IsMultiRegionTrail") for t in trails):
        return []
    return [Finding(
        check_id="LOG-23",
        title="CloudTrail Not Covering All Regions",
        severity=Severity.HIGH,
        resource_arn="account",
        raw_detail="No actively-logging CloudTrail trail covers all regions. "
                   "API activity in regions outside any single-region trail's "
                   "home region is invisible to you.",
        account_context="cloudtrail",
    )]


def check_24_cloudtrail_logs_not_encrypted(trails: list) -> list[Finding]:
    """LOG-24: per-trail, unlike 22/23 — each actively-logging trail
    without a KmsKeyId is its own separate finding, since each trail's
    logs are an independent risk. Stopped trails are skipped here;
    checks 22/23 already cover that gap."""
    findings = []
    for t in trails:
        if not t["IsLogging"]:
            continue
        if t.get("KmsKeyId"):
            continue
        findings.append(Finding(
            check_id="LOG-24",
            title="CloudTrail Logs Not Encrypted",
            severity=Severity.HIGH,
            resource_arn=t["TrailARN"],
            raw_detail=f"Trail '{t['Name']}' has no KMS key configured — its logs in "
                       f"S3 rely on default encryption rather than a customer-managed "
                       f"key, so access to the encryption key can't be controlled or "
                       f"revoked independently of S3 bucket permissions.",
            account_context=f"trail={t['Name']}",
        ))
    return findings


def check_25_guardduty_not_enabled(guardduty) -> list[Finding]:
    """LOG-25: GuardDuty is free to enable and provides automated threat
    detection. Region-scoped, matching this project's single-region
    scope throughout — a true multi-region check would call this once
    per enabled region, out of MVP scope for the same reason.

    SubscriptionRequiredException means the account has NEVER activated
    GuardDuty at all — not a permissions problem (that would be
    AccessDenied), a genuine "this service has never been touched"
    signal. That IS the condition this check exists to catch, so it's
    treated as zero detectors, not re-raised. A real customer account
    with GuardDuty genuinely off is exactly the account most likely to
    throw this, so crashing here would break the check precisely where
    it matters most."""
    try:
        detector_ids = guardduty.list_detectors()["DetectorIds"]
    except ClientError as e:
        if e.response["Error"]["Code"] != "SubscriptionRequiredException":
            raise
        detector_ids = []
    if detector_ids:
        return []
    return [Finding(
        check_id="LOG-25",
        title="GuardDuty Not Enabled",
        severity=Severity.HIGH,
        resource_arn="account",
        raw_detail="GuardDuty is not enabled in this region. It's free to turn on "
                   "and provides automated threat detection (unusual API calls, "
                   "known-malicious IPs, compromised credentials) — with it off, "
                   "there is no automated detection layer at all.",
        account_context="guardduty",
    )]


def run_all(session) -> list[Finding]:
    """Run LOG-22 through LOG-25."""
    cloudtrail = session.client("cloudtrail")
    guardduty = session.client("guardduty")
    trails = _trails_with_status(cloudtrail)

    findings = []
    findings += check_22_cloudtrail_not_enabled(trails)
    findings += check_23_cloudtrail_not_all_regions(trails)
    findings += check_24_cloudtrail_logs_not_encrypted(trails)
    findings += check_25_guardduty_not_enabled(guardduty)
    return findings
