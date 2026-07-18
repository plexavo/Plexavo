"""Category 1: IAM Hygiene & Exposure — checks 7-14.

Distinct from checks 1-6 in iam.py (privesc PATHS — can this principal
escalate to admin). These are standing-risk hygiene findings that exist
independent of any active escalation chain.

Ground-truth honesty, per check — read this before assuming any of these
are validated the same way:
- IAM-07, IAM-08, IAM-11: fully AWS-verifiable today, same discipline as
  checks 1-6.
- IAM-09, IAM-10: age-based checks. AWS won't let Terraform backdate
  CreateDate or fake login history, so a genuine 90-day-old key/dormant
  user can't be manufactured in one session. Ground-truthed instead via
  threshold parametrization — see docs/IAM-HYGIENE-TEST-MATRIX.md for
  how (the one-off validation script used isn't part of this public
  repo; the offline tests in tests/test_iam_hygiene_offline.py are what
  actually run in CI).
  That proves the comparison logic, not the real-world 90-day scenario.
- IAM-13 (Root MFA): read-only validation against the real root account
  state only. We will not disable real root MFA to manufacture a
  positive case — same call made in Day 1. No synthetic ground truth
  exists for this check, structurally, not just today.
- IAM-14 (Lambda admin roles): logic + offline tests only in this pass.
  Live ground truth needs an actual Lambda function, which needs the
  `archive` Terraform provider to package a deployment zip — deferred to
  its own round, same pattern NET-04 followed.
- IAM-12 (Root Usage via CloudTrail): built below. Same ground-truth
  limitation as IAM-13 — only the negative case (no root usage -> silent)
  can be validated against real account state; we will not log in as
  root to manufacture a positive test case. Uses cloudtrail:LookupEvents,
  confirmed against the real service model before writing (Username IS
  a valid LookupAttributes AttributeKey), with a client-side check on
  each event's raw userIdentity.type == "Root" as an extra confirmation
  layer beyond the server-side filter.
"""

import json
import re
from datetime import datetime, timedelta, timezone

from plexavo.findings import Finding, Severity
from plexavo.principals import Principal, _normalize


def _extract_account_ids(aws_principal_field) -> set:
    """Principal.AWS can be a bare 12-digit account ID or a full ARN.
    Extract account IDs from either form, ignoring '*'."""
    if aws_principal_field is None:
        return set()
    vals = _normalize(aws_principal_field)
    ids = set()
    for v in vals:
        if v == "*":
            continue
        if re.match(r"^\d{12}$", v):
            ids.add(v)
            continue
        m = re.match(r"^arn:aws:iam::(\d{12}):", v)
        if m:
            ids.add(m.group(1))
    return ids


def check_07_cross_account_wildcard_trust(principals: list[Principal]) -> list[Finding]:
    """IAM-07: trust policy allows Principal: '*' or {'AWS': '*'} — anyone
    with an AWS account can attempt to assume this role."""
    findings = []
    for p in principals:
        if p.type != "role" or not p.trust_policy:
            continue
        for stmt in _normalize(p.trust_policy.get("Statement")):
            if stmt.get("Effect") != "Allow":
                continue
            principal_field = stmt.get("Principal")
            is_wildcard = principal_field == "*" or (
                isinstance(principal_field, dict) and "*" in _normalize(principal_field.get("AWS"))
            )
            if is_wildcard:
                findings.append(Finding(
                    check_id="IAM-07",
                    title="Cross-Account Trust with Wildcard",
                    severity=Severity.HIGH,
                    resource_arn=p.arn,
                    raw_detail=f"Role '{p.name}' trust policy allows Principal: \"*\" — ANY "
                               f"AWS account can attempt to assume this role, subject only "
                               f"to any Condition present (not evaluated automatically here).",
                    account_context="trust_policy",
                ))
    return findings


def check_08_cross_account_external(principals: list[Principal], own_account_id: str) -> list[Finding]:
    """IAM-08: trust policy allows an AWS account other than this one.
    Not inherently wrong — must be intentional and documented."""
    findings = []
    for p in principals:
        if p.type != "role" or not p.trust_policy:
            continue
        for stmt in _normalize(p.trust_policy.get("Statement")):
            if stmt.get("Effect") != "Allow":
                continue
            principal_field = stmt.get("Principal")
            aws_field = principal_field.get("AWS") if isinstance(principal_field, dict) else None
            external_ids = _extract_account_ids(aws_field) - {own_account_id}
            for ext_id in sorted(external_ids):
                findings.append(Finding(
                    check_id="IAM-08",
                    title="Cross-Account Trust to External Account",
                    severity=Severity.HIGH,
                    resource_arn=p.arn,
                    raw_detail=f"Role '{p.name}' trust policy allows AWS account {ext_id} "
                               f"— outside this account ({own_account_id}) — to assume it. "
                               f"Confirm this is a known, intentional relationship (e.g. a "
                               f"vendor or CI/CD provider), not leftover or unexplained.",
                    account_context=f"external_account={ext_id}",
                ))
    return findings


def check_09_dormant_console_users(iam, users_raw: list, threshold_days: int = 90) -> list[Finding]:
    """IAM-09: console access enabled, but never used or unused for
    threshold_days+. threshold_days is parametrized specifically so
    ground truth can validate the comparison logic against a freshly
    created identity — see module docstring."""
    findings = []
    now = datetime.now(timezone.utc)
    for u in users_raw:
        try:
            iam.get_login_profile(UserName=u["UserName"])
            has_console_access = True
        except iam.exceptions.NoSuchEntityException:
            has_console_access = False
        if not has_console_access:
            continue

        create_age_days = (now - u["CreateDate"]).days
        last_used = u.get("PasswordLastUsed")
        if last_used is None:
            is_dormant = create_age_days >= threshold_days
            basis = f"never logged in (account created {create_age_days} days ago)"
        else:
            dormant_days = (now - last_used).days
            is_dormant = dormant_days >= threshold_days
            basis = f"last console login {dormant_days} days ago"

        if is_dormant:
            findings.append(Finding(
                check_id="IAM-09",
                title="Unused IAM User with Console Access",
                severity=Severity.HIGH,
                resource_arn=u["Arn"],
                raw_detail=f"User '{u['UserName']}' has console access enabled but {basis} "
                           f"(threshold: {threshold_days} days). Dormant credentials with "
                           f"standing access are risk without benefit.",
                account_context=f"threshold_days={threshold_days}",
            ))
    return findings


def check_10_old_access_keys(
    iam, users_raw: list, high_threshold_days: int = 90, critical_threshold_days: int = 180
) -> list[Finding]:
    """IAM-10: active access key older than threshold. High at 90 days,
    Critical at 180, per the blueprint. Thresholds parametrized for the
    same ground-truth reason as check_09."""
    findings = []
    now = datetime.now(timezone.utc)
    for u in users_raw:
        keys = iam.list_access_keys(UserName=u["UserName"])["AccessKeyMetadata"]
        for k in keys:
            if k.get("Status") != "Active":
                continue
            age_days = (now - k["CreateDate"]).days
            if age_days >= critical_threshold_days:
                severity = Severity.CRITICAL
            elif age_days >= high_threshold_days:
                severity = Severity.HIGH
            else:
                continue
            findings.append(Finding(
                check_id="IAM-10",
                title="IAM Access Key Older Than Threshold",
                severity=severity,
                resource_arn=u["Arn"],
                raw_detail=f"Access key {k['AccessKeyId']} on user '{u['UserName']}' is "
                           f"{age_days} days old (created {k['CreateDate'].date()}). Static "
                           f"credentials should be rotated regularly — the longer a key "
                           f"lives, the larger the window of opportunity if it's ever leaked.",
                account_context=f"key_id={k['AccessKeyId']}",
            ))
    return findings


def check_11_multiple_active_keys(iam, users_raw: list) -> list[Finding]:
    """IAM-11: more than one active access key on a single user."""
    findings = []
    for u in users_raw:
        keys = iam.list_access_keys(UserName=u["UserName"])["AccessKeyMetadata"]
        active_keys = [k for k in keys if k.get("Status") == "Active"]
        if len(active_keys) > 1:
            key_ids = ", ".join(k["AccessKeyId"] for k in active_keys)
            findings.append(Finding(
                check_id="IAM-11",
                title="Multiple Active Access Keys",
                severity=Severity.HIGH,
                resource_arn=u["Arn"],
                raw_detail=f"User '{u['UserName']}' has {len(active_keys)} active access "
                           f"keys ({key_ids}). A second active key often means one was "
                           f"forgotten — review whether both are still needed.",
                account_context=f"key_count={len(active_keys)}",
            ))
    return findings


def check_12_root_account_usage(cloudtrail, lookback_days: int = 90) -> list[Finding]:
    """IAM-12: any CloudTrail event attributed to the root user within the
    lookback window. Returns at most one finding — the point is "root
    usage exists," not an enumeration of every root API call.

    Server-side Username="root" filter narrows the API call volume;
    userIdentity.type == "Root" on the raw event is the actual source of
    truth, checked client-side, since a user literally named "root"
    (not the account root) would otherwise be a false positive from the
    filter alone."""
    start_time = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    paginator = cloudtrail.get_paginator("lookup_events")
    for page in paginator.paginate(
        LookupAttributes=[{"AttributeKey": "Username", "AttributeValue": "root"}],
        StartTime=start_time,
    ):
        for event in page["Events"]:
            raw = json.loads(event["CloudTrailEvent"])
            if raw.get("userIdentity", {}).get("type") != "Root":
                continue
            return [Finding(
                check_id="IAM-12",
                title="Root Account Usage Detected",
                severity=Severity.HIGH,
                resource_arn="root-account",
                raw_detail=f"The root account performed '{event['EventName']}' via "
                           f"{event.get('EventSource', 'unknown source')} on "
                           f"{event['EventTime']}, within the last {lookback_days} days. "
                           f"Root should never be used for routine operations — every "
                           f"action taken as root is unrestricted and can't be "
                           f"permission-limited.",
                account_context=f"event_id={event['EventId']}",
            )]
    return []


def check_13_root_mfa(iam) -> list[Finding]:
    """IAM-13: root account has no MFA device. Read-only — see module
    docstring on why this can never have a synthetic positive test case."""
    findings = []
    summary = iam.get_account_summary()["SummaryMap"]
    if summary.get("AccountMFAEnabled") != 1:
        findings.append(Finding(
            check_id="IAM-13",
            title="Root Account Without MFA",
            severity=Severity.CRITICAL,
            resource_arn="root-account",
            raw_detail="The root account has no MFA device enabled "
                       "(AccountMFAEnabled=0 via GetAccountSummary). Root has "
                       "unrestricted, non-permission-limitable access to the entire "
                       "account — MFA is the only meaningful control available for it.",
            account_context="root",
        ))
    return findings


def check_14_lambda_admin_roles(lambda_client, principals: list[Principal]) -> list[Finding]:
    """IAM-14: a Lambda function's execution role has admin-equivalent
    access. If the function is compromised (code vuln, public trigger,
    dependency compromise), blast radius is full account takeover, not
    just that function. Reuses is_admin_equivalent from checks/iam.py —
    imported locally to avoid a circular import at module load time."""
    from plexavo.checks.iam import is_admin_equivalent

    roles_by_arn = {p.arn: p for p in principals if p.type == "role"}
    findings = []
    seen_roles = set()
    paginator = lambda_client.get_paginator("list_functions")
    for page in paginator.paginate():
        for fn in page["Functions"]:
            role_arn = fn.get("Role")
            if not role_arn or role_arn in seen_roles:
                continue
            seen_roles.add(role_arn)
            role = roles_by_arn.get(role_arn)
            if role and is_admin_equivalent(role):
                findings.append(Finding(
                    check_id="IAM-14",
                    title="Lambda Execution Role with Admin Access",
                    severity=Severity.HIGH,
                    resource_arn=fn["FunctionArn"],
                    raw_detail=f"Lambda function '{fn['FunctionName']}' runs with execution "
                               f"role '{role.name}', which has administrator-equivalent "
                               f"access. A code vulnerability, public trigger, or dependency "
                               f"compromise in this function means full account takeover, "
                               f"not just this function's blast radius.",
                    account_context=f"role={role_arn}",
                ))
    return findings


def run_all(session, principals: list[Principal], own_account_id: str) -> list[Finding]:
    """Run checks 7-14, all of them — IAM-12 is now built."""
    iam = session.client("iam")
    lambda_client = session.client("lambda")
    cloudtrail = session.client("cloudtrail")

    users_raw = []
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        users_raw.extend(page["Users"])

    findings = []
    findings += check_07_cross_account_wildcard_trust(principals)
    findings += check_08_cross_account_external(principals, own_account_id)
    findings += check_09_dormant_console_users(iam, users_raw)
    findings += check_10_old_access_keys(iam, users_raw)
    findings += check_11_multiple_active_keys(iam, users_raw)
    findings += check_12_root_account_usage(cloudtrail)
    findings += check_13_root_mfa(iam)
    findings += check_14_lambda_admin_roles(lambda_client, principals)
    return findings
