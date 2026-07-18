"""Category 2: Network Exposure — checks NET-01 through NET-04.

Same methodology as Category 1: don't flag a security group rule in
isolation. A wide-open rule attached to nothing, or attached only to a
private instance, isn't exploitable. Every check here verifies the rule
is actually attached to a resource with a public IP (EC2) or a public
endpoint (RDS) before flagging — mirrors check_04/05's "does a viable
target actually exist" verification from Category 1.

NET-04 (RDS) ships today with full logic + offline tests, but its
Terraform ground truth is deferred to a follow-up round — RDS
provisioning is 5-10 minutes each way, unlike the ~1 minute EC2 takes.
Treat NET-04 as offline-verified only until that round runs.
"""

from plexavo.findings import Finding, Severity

ADMIN_PORTS = {
    22: "SSH",
    3389: "RDP",
    5985: "WinRM (HTTP)",
    5986: "WinRM (HTTPS)",
}

DATABASE_PORTS = {
    3306: "MySQL/MariaDB",
    5432: "PostgreSQL",
    1433: "MSSQL",
    1521: "Oracle",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
    11211: "Memcached",
    5984: "CouchDB",
    9042: "Cassandra",
}


def _rule_is_open_to_internet(rule: dict) -> bool:
    for r in rule.get("IpRanges", []):
        if r.get("CidrIp") == "0.0.0.0/0":
            return True
    for r in rule.get("Ipv6Ranges", []):
        if r.get("CidrIpv6") == "::/0":
            return True
    return False


def analyze_security_groups(ec2) -> dict:
    """sg_id -> {'name': str, 'open_ranges': [(from,to)], 'all_ports_open': bool,
    'all_protocols': bool}
    open_ranges only includes port ranges reachable from 0.0.0.0/0 or ::/0 —
    internally-scoped rules (e.g. from another SG, or a specific office CIDR)
    are correctly excluded, same "don't overclaim" principle as everywhere else.

    'all_ports_open' fires on two distinct cases, both severe enough to
    flag: a genuine IpProtocol="-1" rule (truly every protocol), or a
    specific protocol (e.g. TCP) with its full 0-65535 range open.
    'all_protocols' distinguishes which one it actually was — confirmed
    as a real wording gap via a live scan: a TCP-only full-range rule
    was being described as "all ports and protocols," overclaiming
    protocol coverage (UDP/ICMP aren't touched by a TCP-scoped rule)
    even though the underlying finding (every TCP port reachable) is
    still genuinely severe on its own."""
    result = {}
    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        for sg in page["SecurityGroups"]:
            open_ranges = []
            all_open = False
            all_protocols = False
            for rule in sg.get("IpPermissions", []):
                if not _rule_is_open_to_internet(rule):
                    continue
                if rule.get("IpProtocol") == "-1":
                    all_open = True
                    all_protocols = True
                    continue
                from_port = rule.get("FromPort")
                to_port = rule.get("ToPort")
                if from_port is None or to_port is None:
                    continue
                open_ranges.append((from_port, to_port))
                if from_port == 0 and to_port == 65535:
                    all_open = True
            result[sg["GroupId"]] = {
                "name": sg.get("GroupName", sg["GroupId"]),
                "open_ranges": open_ranges,
                "all_ports_open": all_open,
                "all_protocols": all_protocols,
            }
    return result


def _sg_open_ports(info: dict, port_labels: dict) -> dict:
    """Which of port_labels {port: label} are open per this sg info."""
    if info["all_ports_open"]:
        return dict(port_labels)
    return {p: label for p, label in port_labels.items()
            if any(lo <= p <= hi for lo, hi in info["open_ranges"])}


def _sg_allows_port(info: dict, port: int) -> bool:
    if info["all_ports_open"]:
        return True
    return any(lo <= port <= hi for lo, hi in info["open_ranges"])


def list_public_instances(ec2) -> list:
    """Yield (instance_id, name, public_ip, [sg_ids]) for running/pending
    instances with a public IP. Stopped instances are excluded — without
    an Elastic IP a stopped instance doesn't retain its public IP, and
    conflating "was public" with "is public" would be a real accuracy
    problem, not a rounding error, for a report claiming current exposure."""
    instances = []
    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate(Filters=[
        {"Name": "instance-state-name", "Values": ["pending", "running"]}
    ]):
        for reservation in page["Reservations"]:
            for instance in reservation["Instances"]:
                public_ip = instance.get("PublicIpAddress")
                if not public_ip:
                    continue
                name = next(
                    (t["Value"] for t in instance.get("Tags", []) if t["Key"] == "Name"),
                    instance["InstanceId"],
                )
                sg_ids = [sg["GroupId"] for sg in instance.get("SecurityGroups", [])]
                instances.append((instance["InstanceId"], name, public_ip, sg_ids))
    return instances


def check_net01_admin_port_open(sg_map: dict, instances: list) -> list[Finding]:
    """NET-01: SSH/RDP/WinRM reachable from the internet on a public instance."""
    findings = []
    for instance_id, name, public_ip, sg_ids in instances:
        for sg_id in sg_ids:
            info = sg_map.get(sg_id)
            if not info:
                continue
            hits = _sg_open_ports(info, ADMIN_PORTS)
            if not hits:
                continue
            ports_desc = ", ".join(f"{p} ({label})" for p, label in sorted(hits.items()))
            findings.append(Finding(
                check_id="NET-01",
                title="Admin Port Open to the Internet",
                severity=Severity.CRITICAL,
                resource_arn=instance_id,
                raw_detail=f"EC2 instance '{name}' ({instance_id}), public IP {public_ip}, "
                           f"has security group '{info['name']}' ({sg_id}) allowing "
                           f"{ports_desc} from 0.0.0.0/0 or ::/0 — directly reachable "
                           f"from anywhere on the internet, no network-level restriction.",
                account_context=f"security_group={sg_id}",
            ))
    return findings


def check_net02_database_port_open(sg_map: dict, instances: list) -> list[Finding]:
    """NET-02: A database/cache port reachable from the internet on a public instance."""
    findings = []
    for instance_id, name, public_ip, sg_ids in instances:
        for sg_id in sg_ids:
            info = sg_map.get(sg_id)
            if not info:
                continue
            hits = _sg_open_ports(info, DATABASE_PORTS)
            if not hits:
                continue
            ports_desc = ", ".join(f"{p} ({label})" for p, label in sorted(hits.items()))
            findings.append(Finding(
                check_id="NET-02",
                title="Database Port Open to the Internet",
                severity=Severity.CRITICAL,
                resource_arn=instance_id,
                raw_detail=f"EC2 instance '{name}' ({instance_id}), public IP {public_ip}, "
                           f"has security group '{info['name']}' ({sg_id}) allowing "
                           f"{ports_desc} from 0.0.0.0/0 or ::/0 — a database or cache "
                           f"port is directly reachable from the internet.",
                account_context=f"security_group={sg_id}",
            ))
    return findings


def check_net03_all_ports_open(sg_map: dict, instances: list) -> list[Finding]:
    """NET-03: A security group allows ALL ports from the internet,
    attached to a public instance. Deliberately independent of NET-01/02 —
    stacking is intentional (same pattern as IAM checks), it shows the
    actual blast radius, not just the single worst port.

    Wording is protocol-aware — see analyze_security_groups' docstring
    for why: a genuine protocol="-1" rule and a TCP-only full-range rule
    are both severe, but only the former is actually "all protocols."""
    findings = []
    for instance_id, name, public_ip, sg_ids in instances:
        for sg_id in sg_ids:
            info = sg_map.get(sg_id)
            if not info or not info["all_ports_open"]:
                continue
            scope = "ALL ports and protocols" if info["all_protocols"] else "ALL ports (this specific rule is scoped to one protocol, not every protocol)"
            findings.append(Finding(
                check_id="NET-03",
                title="All Ports Open to the Internet",
                severity=Severity.CRITICAL,
                resource_arn=instance_id,
                raw_detail=f"EC2 instance '{name}' ({instance_id}), public IP {public_ip}, "
                           f"has security group '{info['name']}' ({sg_id}) allowing "
                           f"{scope} from 0.0.0.0/0 or ::/0 — every service "
                           f"running on this instance, including ones added later, is "
                           f"directly internet-reachable.",
                account_context=f"security_group={sg_id}",
            ))
    return findings


def check_net04_rds_publicly_accessible(session) -> list[Finding]:
    """NET-04: RDS instance with PubliclyAccessible=True AND a security
    group that actually allows its DB port from the internet — the same
    "verify actual exploitability" pattern, not just the PubliclyAccessible
    flag alone (a public endpoint behind a locked-down SG isn't the same
    risk as one that's also wide open).

    NOTE: offline-tested only as of this build — no live AWS ground truth
    yet. See network.py module docstring.
    """
    ec2 = session.client("ec2")
    rds = session.client("rds")
    sg_map = analyze_security_groups(ec2)
    findings = []
    paginator = rds.get_paginator("describe_db_instances")
    for page in paginator.paginate():
        for db in page["DBInstances"]:
            if not db.get("PubliclyAccessible"):
                continue
            db_id = db["DBInstanceIdentifier"]
            engine = db.get("Engine", "unknown")
            port = db.get("Endpoint", {}).get("Port")
            sg_ids = [
                g["VpcSecurityGroupId"] for g in db.get("VpcSecurityGroups", [])
                if g.get("Status") == "active"
            ]
            exposed_sg = None
            for sg_id in sg_ids:
                info = sg_map.get(sg_id)
                if info and port and _sg_allows_port(info, port):
                    exposed_sg = sg_id
                    break
            if not exposed_sg:
                continue  # PubliclyAccessible but no SG actually opens the DB port — not exploitable
            findings.append(Finding(
                check_id="NET-04",
                title="Publicly Accessible Database",
                severity=Severity.CRITICAL,
                resource_arn=db.get("DBInstanceArn", db_id),
                raw_detail=f"RDS instance '{db_id}' ({engine}, port {port}) has "
                           f"PubliclyAccessible=True and security group '{exposed_sg}' "
                           f"allows that port from 0.0.0.0/0 or ::/0 — the database is "
                           f"directly reachable from the internet.",
                account_context=f"engine={engine}",
            ))
    return findings


def run_all(session) -> list[Finding]:
    """Run NET-01 through NET-04 and return the combined finding list."""
    ec2 = session.client("ec2")
    sg_map = analyze_security_groups(ec2)
    instances = list_public_instances(ec2)

    findings = []
    findings += check_net01_admin_port_open(sg_map, instances)
    findings += check_net02_database_port_open(sg_map, instances)
    findings += check_net03_all_ports_open(sg_map, instances)
    findings += check_net04_rds_publicly_accessible(session)
    return findings
