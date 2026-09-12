"""Offline regression tests for plexavo/report/html_report.py and plexavo/report/pdf.py.
No AWS calls, no API calls — pure logic and rendering checks.

These specific cases came from reading an ACTUAL generated PDF, not
from anticipating problems in advance:
- Unpaired ** markers (Claude's markdown isn't always symmetrically paired)
- Inline code backticks wrapping literal asterisks (IAM wildcards like `*:*`)
- Triple-backtick code fences colliding with single-backtick inline-code parsing
- fpdf2's "--" underline marker silently deleting real CLI flags

Run: python test_report_offline.py
"""

import os
import sys
import tempfile

from pypdf import PdfReader

import re

from plexavo.findings import Finding, Severity
from plexavo.report.ai_narration import Explanation
from plexavo.scoring import calculate_score
from plexavo.report.html_report import build_report_data, generate_html, _markdown_inline
from plexavo.report.pdf import generate_pdf, _prepare_markdown
from plexavo.attack_paths import AttackChain, ChainNode

failures = 0


def assert_true(cond, msg):
    global failures
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {msg}")
    if not cond:
        failures += 1


def f(check_id="IAM-01", severity=Severity.CRITICAL, resource_arn="arn:aws:iam::111111111111:user/test", raw_detail="x"):
    return Finding(check_id=check_id, title="x", severity=severity, resource_arn=resource_arn, raw_detail=raw_detail, account_context="x")


print("=== build_report_data: basic assembly ===")
findings = [f("IAM-01", Severity.CRITICAL), f("IAM-11", Severity.HIGH)]
score = calculate_score(findings)
data = build_report_data(findings, score, "111111111111", [None, None])
assert_true(len(data["findings_by_severity"]["Critical"]) == 1, "Critical finding correctly bucketed")
assert_true(len(data["findings_by_severity"]["High"]) == 1, "High finding correctly bucketed")
assert_true(data["account_id"] == "111111111111", "Account ID passed through correctly")

print("\n=== build_report_data: mismatched-length explanations raises, doesn't silently misalign ===")
try:
    build_report_data(findings, score, "111111111111", [None])
    assert_true(False, "Should have raised ValueError for mismatched lengths")
except ValueError:
    assert_true(True, "Raises ValueError rather than silently misaligning findings to explanations")

print("\n=== HTML: _markdown_inline handles paired bold and inline code ===")
result = _markdown_inline("The **quick** fix uses `aws iam list-users`")
assert_true("<strong>quick</strong>" in result, f"Paired bold converts to <strong> (got: {result})")
assert_true("<code>aws iam list-users</code>" in result, f"Inline code converts to <code> (got: {result})")

print("\n=== HTML: REGRESSION — unpaired ** doesn't leak through literally ===")
result = _markdown_inline("Detach the policy immediately:**")
assert_true("**" not in result, f"Unpaired ** is stripped, not left literal (got: {result})")

print("\n=== HTML: REGRESSION — IAM wildcard in inline code doesn't collide ===")
result = _markdown_inline("grants unrestricted `*:*` permissions")
assert_true("<code>*:*</code>" in result, f"Wildcard renders cleanly inside <code>, no collision (got: {result})")
assert_true("***" not in result, "No asterisk collision garbage")

print("\n=== HTML: REGRESSION — triple-backtick fence doesn't leave stray single backticks ===")
result = _markdown_inline("Run this:\n```bash\naws iam list-users\n```\nThen check.")
assert_true("`" not in result.replace("<code>", "").replace("</code>", ""), f"No stray backticks survive (got: {result})")

print("\n=== HTML: real <, >, & in AI output still gets escaped (safety not broken by the markdown filter) ===")
result = _markdown_inline("if x < y & y > z")
assert_true("&lt;" in result and "&gt;" in result and "&amp;" in result, f"Genuine HTML special chars still escaped (got: {result})")

print("\n=== PDF: _prepare_markdown converts inline code to italics, not bold (avoids asterisk collision) ===")
result = _prepare_markdown("grants unrestricted `*:*` permissions")
assert_true("__*:*__" in result, f"Backtick code becomes __wrapped__ italics, not **bold** (got: {result})")
assert_true("***" not in result, "No asterisk collision in the PDF path either")

print("\n=== PDF: REGRESSION — unpaired ** count is fixed to even before reaching fpdf2 ===")
result = _prepare_markdown("Step one:**\n\n**Step two:**")
assert_true(result.count("**") % 2 == 0, f"Marker count is always even after cleanup (got {result.count('**')} in: {result!r})")

print("\n=== PDF: REGRESSION — triple-backtick fences stripped before single-backtick parsing runs ===")
result = _prepare_markdown("Run:\n```bash\naws iam list-users\n```\nDone.")
assert_true("`" not in result, f"No stray backticks survive fence stripping (got: {result!r})")

print("\n=== PDF: REGRESSION — real CLI flags survive full generation, not just the prepare step ===")
findings = [f("IAM-03", Severity.CRITICAL)]
explanations = [Explanation(
    impact="Uses `AdministratorAccess` directly. Calls `iam:CreatePolicyVersion` to escalate.",
    how_to_fix="```bash\naws iam detach-user-policy --user-name lab-admin --policy-arn arn:aws:iam::aws:policy/AdministratorAccess\n```",
    next_step="Run `aws iam detach-user-policy --user-name lab-admin --policy-arn arn:aws:iam::aws:policy/AdministratorAccess` now.",
    source="api",
)]
score = calculate_score(findings)
data = build_report_data(findings, score, "111111111111", explanations)
with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
    generate_pdf(data, tmp.name)
    reader = PdfReader(tmp.name)
    text = "\n".join(p.extract_text() for p in reader.pages)
    assert_true("--user-name" in text and "--policy-arn" in text, "Real CLI flags survive full PDF generation intact")
    assert_true("**" not in text, "No stray ** in the final rendered PDF")
os.unlink(tmp.name)

print("\n=== PDF: REGRESSION — no justify-stretch spacing artifacts ===")
# fpdf2's multi_cell() defaults to JUSTIFY alignment, not left — this
# was never caught by text-extraction-based testing (pypdf extracts
# logical words, not visual glyph spacing) and only surfaced when the
# actual rendered PDF was read directly. Justify-stretch shows up as
# large numeric spacing adjustments inside the PDF's TJ text-positioning
# arrays; a correctly left-aligned line has none.
import re as _re


def _max_spacing_adjustment(pdf_path):
    reader = PdfReader(pdf_path)
    max_adj = 0
    for page in reader.pages:
        raw = page.get_contents().get_data().decode("latin-1", errors="replace")
        for array_content in _re.findall(r"\[(.*?)\]\s*TJ", raw, _re.DOTALL):
            outside_parens = _re.sub(r"\([^)]*\)", " ", array_content)
            nums = [float(n) for n in _re.findall(r"-?\d+\.?\d*", outside_parens)]
            if nums:
                max_adj = max(max_adj, max(abs(n) for n in nums))
    return max_adj


findings = [f("IAM-01", Severity.CRITICAL)]
explanations = [Explanation(
    impact="Full admin access with no restriction. x",
    how_to_fix="aws iam detach-user-policy --user-name lab-admin --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
    next_step="Detach the policy now.",
    source="api",
)]
score = calculate_score(findings)
data = build_report_data(findings, score, "111111111111", explanations)
with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
    generate_pdf(data, tmp.name)
    max_adjustment = _max_spacing_adjustment(tmp.name)
    assert_true(max_adjustment < 10, f"No justify-stretch spacing (max adjustment: {max_adjustment}, should be near 0)")
os.unlink(tmp.name)

print("\n=== HTML: Visual Attack Path / Important / All Findings tabs (#3) ===")


def _balanced_divs(html):
    return len(re.findall(r"<div\b", html)) == len(re.findall(r"</div>", html))


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

data = build_report_data(chain_findings, chain_score, "634848780754", [None, None], chains=chains)
html = generate_html(data)

assert_true("Attack Path 1" in html and "Attack Path 2" in html, "Both attack paths get their own labeled section")
assert_true(html.count('class="stepper"') == 2, "Two stepper blocks rendered, one per chain")
assert_true('data-tab-panel="path"' in html and 'data-tab-panel="important"' in html and 'data-tab-panel="all"' in html, "All three tab panels present")
assert_true(html.count('id="chain-iam-role-app-server-role"') == 1, "A node shared by both chains gets exactly one Important card, not two")
assert_true("Breaks 2 of 2 attack paths if fixed" in html, "The shared node's card shows breaks 2 of 2")
assert_true("Breaks 1 of 2 attack paths if fixed" in html, "A non-shared node's card shows breaks 1 of 2")
assert_true('<span class="check-id">NET-01</span>' in html, "A chain node backed by a real finding shows that finding's real check_id, not a fabricated one")
assert_true('<span class="check-id">IAM role</span>' in html, "A chain node with no backing finding falls back to its own title as the badge - never a fake check code")
assert_true("STOR-19" in html, "A real finding that isn't part of any chain still appears in All Findings")
assert_true("activate('path')" in html, "Default active tab is Visual Attack Path when chains exist")
assert_true(_balanced_divs(html), "Rendered HTML has balanced <div>/</div> tags")

print("\n=== HTML: zero chains gets an honest empty state, not a blank tab or an implied clean bill ===")
empty_data = build_report_data(chain_findings, chain_score, "634848780754", [None, None], chains=[])
empty_html = generate_html(empty_data)
assert_true("No attack chains were identified in this scan" in empty_html, "Empty-state text shown on Visual Attack Path")
assert_true("does not guarantee the account has no real attack paths" in empty_html, "Empty-state text stays honest - never implies a clean scan")
assert_true("activate('all')" in empty_html, "Default active tab falls back to All Findings when there are zero chains")
assert_true(_balanced_divs(empty_html), "Rendered HTML has balanced <div>/</div> tags with zero chains")

print("\n=== HTML: chains= omitted entirely behaves like chains=[] (existing callers, e.g. pdf.py's shared build_report_data) ===")
omitted_data = build_report_data(chain_findings, chain_score, "634848780754", [None, None])
omitted_html = generate_html(omitted_data)
assert_true("No attack chains were identified in this scan" in omitted_html, "Omitting chains= renders the same empty state as chains=[]")
assert_true(_balanced_divs(omitted_html), "Rendered HTML has balanced <div>/</div> tags with chains= omitted")

print(f"\n{'ALL PASSED' if failures == 0 else f'{failures} FAILURE(S)'}")
sys.exit(1 if failures else 0)
