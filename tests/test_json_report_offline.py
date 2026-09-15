"""Offline regression tests for plexavo/report/json_report.py — the
machine-readable output the Claude Code Agent Skill will eventually
consume. No AWS calls, no API calls.

Run: python test_json_report_offline.py
"""

import json
import sys

from plexavo import __version__
from plexavo.findings import Finding, Severity
from plexavo.report.ai_narration import Explanation
from plexavo.scoring import calculate_score
from plexavo.report.json_report import build_json_report, SCHEMA_VERSION, DISCLOSED_LIMITATIONS
from plexavo.attack_paths import AttackChain, ChainNode

failures = 0


def assert_true(cond, msg):
    global failures
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {msg}")
    if not cond:
        failures += 1


def f(check_id="IAM-01", severity=Severity.CRITICAL, resource_arn="arn:aws:iam::111111111111:user/test", raw_detail="x"):
    return Finding(check_id=check_id, title="Test Finding", severity=severity, resource_arn=resource_arn,
                    raw_detail=raw_detail, confidence="Confirmed", evidence="granted=1, used=0")


print("=== build_json_report: basic shape ===")
findings = [f("IAM-01", Severity.CRITICAL), f("IAM-11", Severity.HIGH, resource_arn="arn:aws:iam::111111111111:role/x")]
score = calculate_score(findings)
data = build_json_report(findings, score, "111111111111", [None, None])

assert_true(data["schema_version"] == SCHEMA_VERSION, "schema_version present and matches the module constant")
assert_true(data["plexavo_version"] == __version__, "plexavo_version matches the installed package version")
assert_true(data["account_id"] == "111111111111", "account_id passed through correctly")
assert_true(data["score"] == score.score and data["rating"] == score.rating, "score/rating passed through from ScoreResult")
assert_true(data["total_findings"] == 2, "total_findings matches the findings list length")
assert_true(len(data["findings"]) == 2, "findings list has one entry per Finding")
assert_true(data["disclosed_limitations"] == DISCLOSED_LIMITATIONS and len(data["disclosed_limitations"]) > 0,
            "disclosed_limitations always present, never silently dropped")
assert_true(data["attack_chains"] == [] and data["important_findings"] == [], "No chains passed -> both chain views empty")

print("\n=== build_json_report: mismatched-length explanations raises, doesn't silently misalign ===")
try:
    build_json_report(findings, score, "111111111111", [None])
    assert_true(False, "Should have raised ValueError for mismatched lengths")
except ValueError:
    assert_true(True, "Raises ValueError rather than silently misaligning findings to explanations")

print("\n=== build_json_report: findings ordered most-severe-first ===")
mixed = [f("A-1", Severity.LOW), f("A-2", Severity.CRITICAL), f("A-3", Severity.MEDIUM), f("A-4", Severity.HIGH)]
mixed_score = calculate_score(mixed)
mixed_data = build_json_report(mixed, mixed_score, "111111111111", [None] * 4)
assert_true([e["check_id"] for e in mixed_data["findings"]] == ["A-2", "A-4", "A-3", "A-1"],
            "Critical, High, Medium, Low order regardless of original scan order")

print("\n=== build_json_report: explained vs. unexplained findings ===")
exp = Explanation(impact="Full impact prose.", how_to_fix="aws iam ...", source="template",
                   next_step="Run: aws iam ...", confidence="Confirmed", evidence="granted=1, used=0")
explained_findings = [f("IAM-01", Severity.CRITICAL)]
explained_data = build_json_report(explained_findings, calculate_score(explained_findings), "111111111111", [exp])
entry = explained_data["findings"][0]
assert_true(entry["explained"] is True, "A finding with a real how_to_fix + next_step is marked explained")
assert_true(entry["impact"] == "Full impact prose." and entry["next_step"] == "Run: aws iam ..." and entry["how_to_fix"] == "aws iam ...",
            "Explanation content passed through unchanged, never rewritten")

unexplained_findings = [f("IAM-01", Severity.CRITICAL, raw_detail="raw technical detail")]
unexplained_data = build_json_report(unexplained_findings, calculate_score(unexplained_findings), "111111111111", [None])
u_entry = unexplained_data["findings"][0]
assert_true(u_entry["explained"] is False, "A finding with no Explanation is marked not explained")
assert_true(u_entry["impact"] == "raw technical detail" and u_entry["next_step"] == "" and u_entry["how_to_fix"] == "",
            "Falls back to raw_detail as impact, empty next_step/how_to_fix, never fabricated content")

print("\n=== build_json_report: chain_breaks_count, confidence, evidence all pass through from the Finding ===")
chained = f("IAM-06", Severity.CRITICAL)
chained.chain_breaks_count = 2
chained_data = build_json_report([chained], calculate_score([chained]), "111111111111", [None])
c_entry = chained_data["findings"][0]
assert_true(c_entry["chain_breaks_count"] == 2, "chain_breaks_count carried through from the Finding")
assert_true(c_entry["confidence"] == "Confirmed" and c_entry["evidence"] == "granted=1, used=0",
            "confidence/evidence carried through from the Finding, not re-derived")

print("\n=== build_json_report: attack_chains + important_findings (dedup, real-finding-vs-fallback) ===")
chain_findings = [
    f("NET-01", Severity.CRITICAL, resource_arn="i-0a3f9c21", raw_detail="SSH open to the world."),
    f("STOR-19", Severity.CRITICAL, resource_arn="arn:aws:s3:::totally-unrelated-bucket", raw_detail="x"),
]
chain1 = AttackChain(chain_id="path-1", template="ec2-role-s3", nodes=[
    ChainNode(kind="internet", title="Internet", detail="Unauthenticated, from anywhere", resource_id="internet"),
    ChainNode(kind="ec2", title="EC2 instance", detail="i-0a3f9c21 - sg-0d41 allows port 22 from the internet",
              resource_id="i-0a3f9c21", finding_resource_arn="i-0a3f9c21"),
    ChainNode(kind="iam-role", title="IAM role", detail="app-server-role - attached via instance profile",
              resource_id="app-server-role", finding_resource_arn="arn:aws:iam::111111111111:role/app-server-role"),
    ChainNode(kind="s3", title="S3 bucket", detail="plexavo-app-data - role policy grants GetObject",
              resource_id="plexavo-app-data", finding_resource_arn="arn:aws:s3:::plexavo-app-data"),
])
chain2 = AttackChain(chain_id="path-2", template="ec2-role-role", nodes=[
    ChainNode(kind="internet", title="Internet", detail="Unauthenticated, from anywhere", resource_id="internet"),
    ChainNode(kind="ec2", title="EC2 instance", detail="i-0b2c111 - sg-x allows port 3389 from the internet",
              resource_id="i-0b2c111", finding_resource_arn="i-0b2c111"),
    ChainNode(kind="iam-role", title="IAM role", detail="jump-role - attached via instance profile",
              resource_id="jump-role", finding_resource_arn="arn:aws:iam::111111111111:role/jump-role"),
    # Same (kind, resource_id) as chain1's role node - a genuinely shared node across both chains.
    ChainNode(kind="iam-role", title="IAM role", detail="app-server-role - admin-equivalent, reachable via sts:AssumeRole",
              resource_id="app-server-role", finding_resource_arn="arn:aws:iam::111111111111:role/app-server-role"),
])
chains = [chain1, chain2]
chain_score = calculate_score(chain_findings)
chain_data = build_json_report(chain_findings, chain_score, "634848780754", [None, None], chains=chains)

assert_true(len(chain_data["attack_chains"]) == 2, "Two attack chains present")
assert_true(chain_data["attack_chains"][0]["number"] == 1 and chain_data["attack_chains"][1]["number"] == 2,
            "Chains numbered 1 and 2, in order")
assert_true(chain_data["attack_chains"][0]["template"] == "ec2-role-s3", "Chain template name passed through")
assert_true(len(chain_data["attack_chains"][0]["nodes"]) == 4, "All 4 nodes present on chain 1 (internet included)")

shared = [c for c in chain_data["important_findings"] if c["resource"] == "app-server-role"]
assert_true(len(shared) == 1, "A node shared by both chains gets exactly one important_findings entry, not two")
assert_true(shared[0]["breaks_count"] == 2 and shared[0]["total_chains"] == 2,
            "The shared node's card shows breaks_count 2 of total_chains 2")

net01_card = [c for c in chain_data["important_findings"] if c["check_id"] == "NET-01"]
assert_true(len(net01_card) == 1, "A chain node backed by a real finding (i-0a3f9c21 / NET-01) surfaces that finding's real check_id")

jump_role_card = [c for c in chain_data["important_findings"] if c["resource"] == "jump-role"]
assert_true(len(jump_role_card) == 1 and jump_role_card[0]["check_id"] is None and jump_role_card[0]["badge"] == "IAM role",
            "A chain node with no backing finding falls back to its own title as the badge, never a fabricated check code")

assert_true(any(c["check_id"] == "STOR-19" for c in chain_data["findings"]),
            "A real finding that isn't part of any chain still appears in the plain findings list")

print("\n=== build_json_report: output is actually valid, serializable JSON ===")
try:
    serialized = json.dumps(chain_data)
    assert_true(json.loads(serialized) == chain_data, "Round-trips through json.dumps/json.loads unchanged")
except (TypeError, ValueError) as e:
    assert_true(False, f"json.dumps raised: {e}")

print("\n=== build_json_report: zero findings and zero chains ===")
empty_data = build_json_report([], calculate_score([]), "111111111111", [], chains=[])
assert_true(empty_data["findings"] == [] and empty_data["attack_chains"] == [] and empty_data["important_findings"] == [],
            "Empty scan produces empty lists, not an error or a fabricated 'all clear' claim beyond what score/rating already say")
assert_true(empty_data["total_findings"] == 0, "total_findings is 0")

print(f"\n{'ALL PASSED' if failures == 0 else f'{failures} FAILURE(S)'}")
sys.exit(1 if failures else 0)
