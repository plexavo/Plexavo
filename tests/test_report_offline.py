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

from plexavo.findings import Finding, Severity
from plexavo.report.ai_narration import Explanation
from plexavo.scoring import calculate_score
from plexavo.report.html_report import build_report_data, generate_html, _markdown_inline
from plexavo.report.pdf import generate_pdf, _prepare_markdown

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

print(f"\n{'ALL PASSED' if failures == 0 else f'{failures} FAILURE(S)'}")
sys.exit(1 if failures else 0)
