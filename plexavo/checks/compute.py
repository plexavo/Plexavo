"""Category 7: EC2 Instance Hardening — check 32.

Added after scanning a hand-built "capital_one stack" terraform demo that
reproduces the 2019 Capital One breach shape (internet-facing instance,
IMDSv1 reachable, an over-permissioned role attached) and finding Plexavo
had nothing at all looking at the metadata service — the exact setting
that let the real attack escalate an SSRF into stolen AWS credentials.

Deliberately its own category rather than folded into Network: NET-01/02/03
answer "can something on the internet reach a port on this instance,"
which is a security-group question. IMDSv1 reachability is not gated by
the instance's own security group at all — the request that matters is
loopback-style, from a process already running ON the instance (an SSRF
bug in the app is the classic path) to the link-local metadata address
169.254.169.254. So, unlike every NET-0x check, this one deliberately does
NOT require a public IP or an internet-open security group rule to fire —
gating it on network exposure the way NET-01/02/03 do would make it blind
to the exact scenario it exists to catch.
"""

from plexavo.findings import Finding, Severity


def list_instances_with_metadata(ec2) -> list[dict]:
    """{'instance_id', 'name', 'http_tokens', 'http_endpoint', 'has_role'}
    for every running/pending instance. Stopped instances are excluded —
    same reasoning as network.py's list_public_instances: a finding should
    describe what's actually reachable right now, not a past or future
    state. MetadataOptions is always present on a real DescribeInstances
    response; the .get() defaults here only guard hand-built test fixtures
    that omit it."""
    instances = []
    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate(Filters=[
        {"Name": "instance-state-name", "Values": ["pending", "running"]}
    ]):
        for reservation in page["Reservations"]:
            for instance in reservation["Instances"]:
                name = next(
                    (t["Value"] for t in instance.get("Tags", []) if t["Key"] == "Name"),
                    instance["InstanceId"],
                )
                metadata_options = instance.get("MetadataOptions", {})
                instances.append({
                    "instance_id": instance["InstanceId"],
                    "name": name,
                    "http_tokens": metadata_options.get("HttpTokens", "optional"),
                    "http_endpoint": metadata_options.get("HttpEndpoint", "enabled"),
                    "has_role": bool(instance.get("IamInstanceProfile")),
                })
    return instances


def check_32_imdsv2_not_enforced(instances: list[dict]) -> list[Finding]:
    """EC2-32: the instance's metadata service accepts unauthenticated
    IMDSv1 requests (HttpTokens != 'required') instead of requiring the
    session-token-authenticated IMDSv2.

    An instance with HttpEndpoint == 'disabled' has no metadata service to
    reach at all — correctly not flagged, that's the strongest posture,
    not a gap.

    Severity is genuinely different depending on whether there's anything
    for a stolen token to retrieve:
    - CRITICAL when an IAM instance profile is attached — this is the
      exact chain the 2019 Capital One breach used: SSRF into the app,
      SSRF used to query IMDS, IMDSv1 hands back the attached role's
      temporary credentials with no proof the caller ever reached IMDS
      intentionally, credentials used to reach whatever that role can
      reach.
    - MEDIUM when no role is attached — still a real hardening gap (the
      metadata service still exposes the instance identity document, and
      any secrets accidentally left in user-data), but there's no AWS
      credential sitting behind this specific instance for IMDSv1 to hand
      over, so it doesn't get the same severity as the credential-theft
      case above."""
    findings = []
    for inst in instances:
        if inst["http_endpoint"] != "enabled":
            continue
        if inst["http_tokens"] == "required":
            continue
        if inst["has_role"]:
            severity = Severity.CRITICAL
            role_note = (
                "This instance also has an IAM role attached, so a stolen session token "
                "can retrieve that role's real, temporary AWS credentials — this is the "
                "exact chain (SSRF -> IMDSv1 -> stolen instance-role credentials) that "
                "caused the 2019 Capital One breach."
            )
        else:
            severity = Severity.MEDIUM
            role_note = (
                "No IAM role is attached to this instance, so there are no AWS "
                "credentials for a stolen token to retrieve here — but the metadata "
                "service can still leak the instance identity document and any secrets "
                "left in user-data."
            )
        findings.append(Finding(
            check_id="EC2-32",
            title="IMDSv2 Not Enforced",
            severity=severity,
            resource_arn=inst["instance_id"],
            raw_detail=f"EC2 instance '{inst['name']}' ({inst['instance_id']}) accepts the "
                       f"legacy, unauthenticated IMDSv1 metadata requests instead of "
                       f"requiring IMDSv2's session token. {role_note}",
            account_context=f"iam_role_attached={inst['has_role']}",
            evidence=f"http_tokens={inst['http_tokens']}, iam_role_attached={inst['has_role']}",
        ))
    return findings


def run_all(session) -> list[Finding]:
    """Run EC2-32 against every running/pending instance in the account."""
    ec2 = session.client("ec2")
    instances = list_instances_with_metadata(ec2)
    return check_32_imdsv2_not_enforced(instances)
