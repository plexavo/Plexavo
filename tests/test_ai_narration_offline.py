"""Offline tests for explainer.py. No real API calls anywhere in this
file — the "API path" tests use a fake Anthropic-shaped client.

Run: python test_explainer_offline.py
"""

import sys
from plexavo.findings import Finding, Severity
from plexavo.report.ai_narration import (
    explain_finding,
    _parse_sections,
    _short_name,
    _strip_stray_markdown_headers,
    _strip_leading_markdown_noise,
    COMMON_CHECK_TEMPLATES,
)

failures = 0


def assert_true(cond, msg):
    global failures
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {msg}")
    if not cond:
        failures += 1


def f(check_id, resource_arn="arn:aws:iam::111111111111:role/test-role", raw_detail="x", account_context="x"):
    return Finding(check_id=check_id, title="x", severity=Severity.CRITICAL,
                   resource_arn=resource_arn, raw_detail=raw_detail, account_context=account_context)


class ExplodingClient:
    """A fake Anthropic client that raises if ANY method is touched —
    proves the templated path genuinely never reaches the network,
    not just that it happens not to in this test run."""
    class messages:
        @staticmethod
        def create(**kwargs):
            raise AssertionError("Templated finding should NEVER call the API — this client should never be invoked")


class FakeResponse:
    def __init__(self, text=None, blocks=None, stop_reason="end_turn"):
        self.stop_reason = stop_reason
        if blocks is not None:
            self.content = blocks
        else:
            self.content = [type("Block", (), {"text": text, "type": "text"})()]


class FakeClient:
    def __init__(self, response_text=None, raise_exc=None, response_blocks=None, stop_reason="end_turn"):
        self._text = response_text
        self._raise = raise_exc
        self._blocks = response_blocks
        self._stop_reason = stop_reason
        self.messages = self

    def create(self, **kwargs):
        if self._raise:
            raise self._raise
        if self._blocks is not None:
            return FakeResponse(blocks=self._blocks, stop_reason=self._stop_reason)
        return FakeResponse(text=self._text, stop_reason=self._stop_reason)


print("=== _short_name ===")
assert_true(_short_name("arn:aws:iam::111111111111:role/my-role") == "my-role", "Extracts name after last /")
assert_true(_short_name("arn:aws:s3:::my-bucket") == "my-bucket", "Extracts name after last : when no /")
assert_true(_short_name("i-0abc123") == "i-0abc123", "Bare ID with no separators returned as-is")

print("\n=== All 10 templates produce non-empty, correctly-sourced explanations, with ZERO API contact ===")
for check_id in COMMON_CHECK_TEMPLATES:
    finding = f(check_id)
    result = explain_finding(finding, client=ExplodingClient())
    assert_true(result.source == "template", f"{check_id} routes to template (got source={result.source})")
    assert_true(bool(result.whats_wrong.strip()), f"{check_id} whats_wrong is non-empty")
    assert_true(bool(result.attacker_does.strip()), f"{check_id} attacker_does is non-empty")
    assert_true(bool(result.how_to_fix.strip()), f"{check_id} how_to_fix is non-empty")
assert_true(len(COMMON_CHECK_TEMPLATES) == 10, f"Exactly 10 templated checks exist (got {len(COMMON_CHECK_TEMPLATES)})")

print("\n=== Templated checks correctly substitute the actual resource name, not a placeholder ===")
finding = f("IAM-01", resource_arn="arn:aws:iam::111111111111:user/lab-admin")
result = explain_finding(finding, client=ExplodingClient())
assert_true("lab-admin" in result.whats_wrong, "The real resource name appears in the templated text")

print("\n=== _parse_sections: well-formatted plain output ===")
raw = ("WHAT'S WRONG: The bucket is public.\n\n"
       "WHAT AN ATTACKER DOES: Calls s3:GetObject to read everything.\n\n"
       "HOW TO FIX: Run aws s3api put-public-access-block ...")
w, a, h = _parse_sections(raw)
assert_true(w == "The bucket is public.", f"whats_wrong parsed correctly (got: {w!r})")
assert_true(a == "Calls s3:GetObject to read everything.", f"attacker_does parsed correctly (got: {a!r})")
assert_true(h.startswith("Run aws s3api"), f"how_to_fix parsed correctly (got: {h!r})")

print("\n=== _parse_sections: markdown bold headers, no colon ===")
raw = ("**WHAT'S WRONG** The role is over-permissioned.\n\n"
       "**WHAT AN ATTACKER DOES** Assumes the role directly.\n\n"
       "**HOW TO FIX** Scope the trust policy.")
w, a, h = _parse_sections(raw)
assert_true(w == "The role is over-permissioned.", f"Handles markdown bold + missing colon (got: {w!r})")
assert_true(a == "Assumes the role directly.", "attacker_does parsed with bold headers")
assert_true(h == "Scope the trust policy.", "how_to_fix parsed with bold headers")

print("\n=== _parse_sections: lowercase headers ===")
raw = "what's wrong: x\n\nwhat an attacker does: y\n\nhow to fix: z"
w, a, h = _parse_sections(raw)
assert_true((w, a, h) == ("x", "y", "z"), f"Case-insensitive matching works (got: {(w, a, h)!r})")

print("\n=== _parse_sections: headers not found at all -> raw text preserved, not dropped ===")
raw = "Something went generically wrong with no structure."
w, a, h = _parse_sections(raw)
assert_true(w == raw and a == "" and h == "", "Unparseable text goes entirely into whats_wrong, nothing silently lost")

print("\n=== API path: non-templated check_id, well-formatted fake response ===")
fake_response_text = (
    "WHAT'S WRONG: This role can assume an admin role.\n\n"
    "WHAT AN ATTACKER DOES: Calls sts:AssumeRole on the target role.\n\n"
    "HOW TO FIX: Scope the Resource field to specific roles."
)
finding = f("IAM-05")  # NOT in COMMON_CHECK_TEMPLATES — must go through the API path
result = explain_finding(finding, client=FakeClient(response_text=fake_response_text))
assert_true(result.source == "api", f"Non-templated check routes to the API path (got source={result.source})")
assert_true(result.whats_wrong == "This role can assume an admin role.", "API response parsed correctly end-to-end")

print("\n=== REGRESSION: ThinkingBlock before TextBlock — the exact bug hit in production ===")
# Simulates Sonnet 5's real default behavior: a ThinkingBlock (no .text
# attribute at all, matching the real SDK type) appears at content[0],
# with the actual answer in a TextBlock afterward. This exact shape
# crashed the original content[0].text code with:
# "'ThinkingBlock' object has no attribute 'text'"
thinking_block = type("ThinkingBlock", (), {"type": "thinking", "thinking": ""})()
text_block = type("TextBlock", (), {
    "type": "text",
    "text": "WHAT'S WRONG: x\n\nWHAT AN ATTACKER DOES: y\n\nHOW TO FIX: z",
})()
finding = f("IAM-05")
result = explain_finding(finding, client=FakeClient(response_blocks=[thinking_block, text_block]))
assert_true(result.source == "api", f"Correctly extracts text past a leading ThinkingBlock (got source={result.source})")
assert_true(result.whats_wrong == "x", f"Text content correctly parsed despite the thinking block (got: {result.whats_wrong!r})")

print("\n=== REGRESSION: '##' markdown headings immediately before the label ===")
raw = "## WHAT'S WRONG: x\n\n## WHAT AN ATTACKER DOES: y\n\n## HOW TO FIX: z"
w, a, h = _parse_sections(raw)
assert_true((w, a, h) == ("x", "y", "z"), f"'##' prefix directly on the header is stripped cleanly (got: {(w, a, h)!r})")

print("\n=== REGRESSION: exact production bug — orphaned bare '##' line inside section content ===")
# Matches what was actually observed: a bare '##' line with blank lines
# on both sides, sitting inside what should be clean prose content.
raw = ("WHAT'S WRONG: The role can escalate to admin.\n\n"
       "##\n\n"
       "WHAT AN ATTACKER DOES: An attacker assumes the role directly.\n\n"
       "##\n\n"
       "HOW TO FIX: Remove the assume-role permission.")
w, a, h = _parse_sections(raw)
assert_true("##" not in w and "##" not in a, f"No orphaned '##' fragments leak into parsed content (got w={w!r}, a={a!r})")

print("\n=== _strip_stray_markdown_headers: unit test in isolation ===")
assert_true(_strip_stray_markdown_headers("real content\n\n##\n\nmore content") == "real content\n\nmore content",
            "Bare '##' line removed, surrounding content and spacing preserved")
assert_true(_strip_stray_markdown_headers("### also stripped\nreal line") == "### also stripped\nreal line",
            "A line with real text after the markers is correctly left alone — that's the split regex's job, not this cleanup's")

print("\n=== REGRESSION: exact production bug — colon-BEFORE-asterisks ordering ===")
# Matches what was actually observed this round: 'WHAT'S WRONG: **' —
# opposite order from the earlier '**WHAT'S WRONG:' case already tested.
raw = ("WHAT'S WRONG: ** The role can escalate to admin.\n\n"
       "WHAT AN ATTACKER DOES: ** An attacker assumes the role directly.\n\n"
       "HOW TO FIX: ** Remove the assume-role permission.")
w, a, h = _parse_sections(raw)
assert_true(w == "The role can escalate to admin.", f"Colon-before-asterisks noise stripped cleanly (got: {w!r})")
assert_true("**" not in w and "**" not in a and "**" not in h, "No stray ** survives in any section")

print("\n=== _strip_leading_markdown_noise: unit test, several real orderings in one pass ===")
assert_true(_strip_leading_markdown_noise(": ** real content") == "real content", "colon-then-asterisks")
assert_true(_strip_leading_markdown_noise("** : real content") == "real content", "asterisks-then-colon")
assert_true(_strip_leading_markdown_noise("## real content") == "real content", "hash-then-space")
assert_true(_strip_leading_markdown_noise("real content") == "real content", "no noise — content untouched")
assert_true(_strip_leading_markdown_noise("plain text with ** bold ** later") == "plain text with ** bold ** later",
            "Only LEADING noise is touched — intentional formatting deeper in the text survives untouched")

print("\n=== REGRESSION: truncated response (stop_reason=max_tokens) is flagged, not silently returned ===")
truncated_text = "WHAT'S WRONG: x\n\nWHAT AN ATTACKER DOES: y\n\nHOW TO FIX: Step 1: do this\naws iam delete-role-policy \\\n  --role-name"
finding = f("IAM-05")
result = explain_finding(finding, client=FakeClient(response_text=truncated_text, stop_reason="max_tokens"))
assert_true("TRUNCATED" in result.how_to_fix, f"Truncation is visibly flagged, not silently returned as if complete (got: {result.how_to_fix!r})")

print("\n=== FALSE POSITIVE GUARD: normal, complete response does NOT get flagged as truncated ===")
finding = f("IAM-05")
result = explain_finding(finding, client=FakeClient(response_text=fake_response_text, stop_reason="end_turn"))
assert_true("TRUNCATED" not in result.how_to_fix, "A normal, complete response is not falsely flagged")

print("\n=== API path: exception during the call -> graceful fallback, not a crash ===")
finding = f("IAM-05", raw_detail="original technical detail here")
result = explain_finding(finding, client=FakeClient(raise_exc=ConnectionError("simulated network failure")))
assert_true(result.source == "fallback", f"A failed API call falls back gracefully (got source={result.source})")
assert_true(result.whats_wrong == "original technical detail here", "Fallback preserves the original raw_detail, doesn't lose the finding")
# Per the OSS plan's §3.3 contract: the fallback must be silent in the
# report — no raw exception text ever reaches report-facing content.
# attacker_does/how_to_fix are empty specifically so html_report.py's
# `explained` check (bool(attacker_does) and bool(how_to_fix)) routes
# this through the same clean single-paragraph render as "no
# explanation was ever attempted," not a 3-section layout with a
# Python exception message sitting in HOW TO FIX.
assert_true(result.attacker_does == "", "Fallback leaves attacker_does empty — no partial/misleading content")
assert_true(result.how_to_fix == "", "Fallback never leaks the raw exception into report-facing content")

print("\n=== API path: missing anthropic package (not installed) also falls back cleanly ===")
# `anthropic` is an optional extra — a user who never installed it and
# hits a non-templated finding must get the exact same clean fallback
# as any other API failure, not an ImportError crashing the scan.
import builtins as _builtins
_real_import = _builtins.__import__


def _blocked_import(name, *args, **kwargs):
    if name == "anthropic":
        raise ImportError("simulated: anthropic not installed")
    return _real_import(name, *args, **kwargs)


_builtins.__import__ = _blocked_import
try:
    finding = f("IAM-05", raw_detail="original technical detail here")
    result = explain_finding(finding)
finally:
    _builtins.__import__ = _real_import
assert_true(result.source == "fallback", f"Missing anthropic package falls back, doesn't crash (got source={result.source})")
assert_true(result.how_to_fix == "", "Missing-package fallback is just as silent as any other failure")

print(f"\n{'ALL PASSED' if failures == 0 else f'{failures} FAILURE(S)'}")
sys.exit(1 if failures else 0)
