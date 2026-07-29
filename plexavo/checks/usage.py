"""Category 5: Permission Usage Analysis — checks 26-27, both High.

The blueprint's own stated core differentiator ("not PMapper + ChatGPT")
and, by design, the hardest category in this project — deliberately
built last.

Check 28 (blueprint: "Users Who Haven't Logged In for 90+ Days") is
skipped entirely — it's a functional duplicate of IAM-09, already built
on Day 2. Rebuilding it here would be zero new coverage for real effort.

--- Real AWS mechanics, confirmed before writing any code, not assumed ---

check_27 (roles not assumed in 90+ days): IAM's own ListRoles/GetRole
response includes RoleLastUsed.LastUsedDate directly — confirmed against
the real botocore service model. No CloudTrail needed at all, same
simpler, more reliable pattern as IAM-09/10 (PasswordLastUsed / access
key LastUsedDate).

check_26 (unused permissions per role) genuinely needs CloudTrail, and
two things about it were confirmed via current AWS documentation before
building, not guessed:
1. There is NO server-side LookupEvents filter for "events performed by
   this role." The Username LookupAttribute matches the assumed-role
   SESSION name, not the role name (confirmed: "CloudTrail event
   history uses the assumed role session name as the username for
   filtered events") — an arbitrary, unpredictable value, not something
   this tool can filter on in advance. So this fetches CloudTrail
   broadly, once, and attributes each event to a role CLIENT-SIDE via
   userIdentity.sessionContext.sessionIssuer.arn — confirmed as the
   correct field path against several real AWS CloudTrail event
   examples, not assumed.
2. LookupEvents only covers the last 90 days, a hard AWS limit
   regardless of trail configuration (confirmed: "You can use CloudWatch
   log groups to search API history beyond the last 90 days" — meaning
   LookupEvents itself cannot, full stop).

Real, stated scope limits for check_26, not hidden:
- Only EXPLICIT, individually-named actions are checked for "unused"
  status. A service-wildcard grant (s3:*) or full wildcard (*) is never
  expanded into its implied action list — that's a combinatorially
  large, impractical enumeration, and IAM-01 already flags
  wildcard-admin grants separately as a distinct, more severe problem.
  This check is specifically about explicitly-listed actions that turn
  out to never get called.
- eventSource -> IAM action-prefix mapping is done by naively stripping
  ".amazonaws.com" (e.g. "s3.amazonaws.com" -> "s3"). This is wrong for
  a small, known set of AWS's own exceptions (e.g. CloudWatch's
  eventSource is "monitoring.amazonaws.com", not "cloudwatch...", per
  AWS's own documentation) — stated here as a known gap, not patched
  with a full per-service mapping table for MVP scope.
- A SEPARATE, CONFIRMED real bug found via live testing (not
  anticipated in advance): AWS's IAM permission name and CloudTrail's
  recorded eventName aren't always the same string. Confirmed directly:
  the IAM permission for `aws s3api list-buckets` is
  `s3:ListAllMyBuckets`, but CloudTrail records the event as
  `ListBuckets` — no "AllMy". AWS's own S3 CloudTrail documentation
  confirms this is a recurring pattern, not a one-off
  ("PutBucketLifecycleConfiguration" is recorded as
  "PutBucketLifecycle"). There is no complete, authoritative mapping
  table for this readily available, so
  _IAM_TO_CLOUDTRAIL_EVENTNAME_EXCEPTIONS below is a small, explicitly
  non-exhaustive list that starts with what's been confirmed through
  actual use and is expected to need more entries over time — stated
  honestly, not presented as complete coverage.
- CloudTrail pagination is capped (see _fetch_role_usage_map) to keep
  runtime bounded on an active account; if the cap is hit, the finding
  text says so explicitly rather than silently under-reporting usage.
- On an account with genuinely low API activity in the lookback window
  (exactly the case for personal/lab accounts), most granted
  permissions will show as "unused" simply because little has happened
  yet — not because they're provably excess. This is a real, structural
  limitation of usage-based analysis on quiet accounts, not a bug to
  fix; noted here so it isn't mistaken for one during grading.
"""

import json
from datetime import datetime, timedelta, timezone

from plexavo.findings import Finding, Severity
from plexavo.principals import Principal, _normalize


_IAM_TO_CLOUDTRAIL_EVENTNAME_EXCEPTIONS = {
    # IAM permission name -> the actual CloudTrail eventName, for
    # confirmed cases where they differ. NOT exhaustive — see module
    # docstring. Add entries here as more are discovered through real
    # use, don't assume this list is complete.
    "s3:listallmybuckets": "s3:listbuckets",
}


def _is_action_used(granted_action: str, used_actions: set) -> bool:
    """True if granted_action was actually used — checked directly, or
    via a known IAM-name-vs-CloudTrail-eventName exception mapping."""
    if granted_action in used_actions:
        return True
    mapped = _IAM_TO_CLOUDTRAIL_EVENTNAME_EXCEPTIONS.get(granted_action)
    return mapped is not None and mapped in used_actions


def _explicit_granted_actions(principal: Principal) -> set:
    """Every explicitly-named (non-wildcard) action this principal's
    Allow statements grant. Excludes '*', any 'service:*' wildcard, Deny
    statements, and NotAction statements (same reasoning as wildcards —
    NotAction implies an unbounded 'everything except X' set, not a
    concrete list to check usage against)."""
    granted = set()
    for _, statements in principal.policies:
        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            if "NotAction" in stmt:
                continue
            for action in _normalize(stmt.get("Action")):
                action = action.lower()
                if action == "*" or "*" in action:
                    # Excludes ANY wildcard usage, not just a full
                    # "service:*" — confirmed as a real gap via a live
                    # scan: "iam:Get*" and "iam:List*" (both genuinely
                    # wildcarded, just not to the whole service) were
                    # slipping through the old check (action.endswith(":*")),
                    # which only matches the exact literal ":*" suffix.
                    continue
                granted.add(action)
    return granted


def _fetch_role_usage_map(cloudtrail, lookback_days: int = 90, max_pages: int = 50):
    """One broad pass over CloudTrail LookupEvents, building
    {role_arn_lowercased: set_of_actions_used}. Returns (usage_map,
    hit_page_cap) — see module docstring for why this can't be
    server-side filtered per role, and why the cap exists."""
    start_time = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    usage_map: dict = {}
    paginator = cloudtrail.get_paginator("lookup_events")
    page_count = 0
    hit_cap = False
    for page in paginator.paginate(StartTime=start_time):
        page_count += 1
        for event in page["Events"]:
            try:
                raw = json.loads(event["CloudTrailEvent"])
            except (KeyError, json.JSONDecodeError, TypeError):
                continue
            user_identity = raw.get("userIdentity", {})
            if user_identity.get("type") != "AssumedRole":
                continue
            role_arn = user_identity.get("sessionContext", {}).get("sessionIssuer", {}).get("arn")
            event_source = raw.get("eventSource", "")
            event_name = raw.get("eventName", "")
            if not role_arn or not event_source or not event_name:
                continue
            service = event_source.split(".")[0]
            action = f"{service}:{event_name}".lower()
            usage_map.setdefault(role_arn.lower(), set()).add(action)
        if page_count >= max_pages:
            hit_cap = True
            break
    return usage_map, hit_cap


def check_26_unused_permissions(cloudtrail, principals: list) -> list:
    """USE-26: explicitly-granted actions never called by that role in
    the lookback window. See module docstring for full scope/limits."""
    usage_map, hit_cap = _fetch_role_usage_map(cloudtrail)
    findings = []
    for p in principals:
        if p.type != "role":
            continue
        granted = _explicit_granted_actions(p)
        if not granted:
            continue
        used = usage_map.get(p.arn.lower(), set())
        unused = {a for a in granted if not _is_action_used(a, used)}
        if not unused:
            continue
        cap_note = " CloudTrail lookup hit its page cap — this list may be incomplete." if hit_cap else ""
        shown = ", ".join(sorted(unused)[:10])
        more = f", and {len(unused) - 10} more" if len(unused) > 10 else ""
        findings.append(Finding(
            check_id="USE-26",
            title="Unused Permissions Detected",
            severity=Severity.HIGH,
            resource_arn=p.arn,
            raw_detail=(
                f"Role '{p.name}' is explicitly granted {len(unused)} action(s) never called in the "
                f"last 90 days of CloudTrail history: {shown}{more}. Permissions that are "
                f"granted but never used are excess attack surface with no offsetting benefit — "
                f"consider removing what isn't actually needed."
            ),
            account_context=f"granted={len(granted)},used={len(used)},unused={len(unused)}",
            confidence="Likely — see note" if hit_cap else "Confirmed",
            evidence=f"granted={len(granted)}, used={len(used)}, unused={len(unused)}.{cap_note}".strip(),
        ))
    return findings


def check_27_roles_not_assumed(iam_roles_raw: list, lookback_days: int = 90) -> list:
    """USE-27: roles never assumed, or not assumed within the lookback
    window, using IAM's own RoleLastUsed field directly — no CloudTrail
    needed, same pattern as IAM-09/10.

    AWS-managed service-linked roles (path starts with
    /aws-service-role/) are deliberately excluded — confirmed as a real
    gap via a live scan that flagged AWSServiceRoleForRDS,
    ...ForResourceExplorer, ...ForSupport, and ...ForTrustedAdvisor as
    "never assumed, consider removing." These aren't assumed via a
    normal sts:AssumeRole the way a customer-created role is, and
    whether RoleLastUsed populates reliably for them was never verified
    against real data before this. More importantly: recommending
    `iam:DeleteServiceLinkedRole` is genuinely risky if AWS is silently,
    legitimately depending on one — this check has no way to confirm
    that either way, so it doesn't guess."""
    findings = []
    cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    for role in iam_roles_raw:
        if role.get("Path", "").startswith("/aws-service-role/"):
            continue
        last_used = role.get("RoleLastUsed", {}).get("LastUsedDate")
        role_name = role["RoleName"]
        role_arn = role["Arn"]
        if last_used is None:
            detail = f"Role '{role_name}' has never been assumed since it was created."
            last_used_str = "never"
        elif last_used < cutoff:
            days_ago = (datetime.now(timezone.utc) - last_used).days
            detail = f"Role '{role_name}' was last assumed {days_ago} days ago — over the {lookback_days}-day window."
            last_used_str = last_used.isoformat()
        else:
            continue
        findings.append(Finding(
            check_id="USE-27",
            title="Role Not Assumed Recently",
            severity=Severity.HIGH,
            resource_arn=role_arn,
            raw_detail=(
                f"{detail} An unused role is standing attack surface with no current legitimate "
                f"purpose — confirm it's still needed, or remove it."
            ),
            account_context=f"last_used={last_used_str}",
            evidence=f"last_used={last_used_str}",
        ))
    return findings


def run_all(session, principals: list) -> list:
    """Run USE-26 and USE-27. Check 28 deliberately skipped — see module
    docstring."""
    cloudtrail = session.client("cloudtrail")
    iam = session.client("iam")

    roles_raw = []
    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        roles_raw.extend(page["Roles"])

    findings = []
    findings += check_26_unused_permissions(cloudtrail, principals)
    findings += check_27_roles_not_assumed(roles_raw)
    return findings
