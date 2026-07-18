"""report/ai_narration.py — opt-in Claude API integration for plain-English
finding narratives. Bring-your-own-key: never embeds a project-owned key,
never required to use the tool. No ANTHROPIC_API_KEY set → every finding
uses the template path below or the raw finding detail, zero API calls,
zero cost. See explain_finding() for the fallback contract.

Blueprint spec, verified before building, not paraphrased from memory:
- System prompt: cloud security analyst writing for a startup CTO who's
  never done a security audit. No jargon without explanation. Every
  attack description must name specific AWS API calls. Every fix must
  be copy-pasteable. Name chained resources. Be direct ("Fix this by...").
- User prompt: exactly 3 sections — WHAT'S WRONG (1 sentence),
  WHAT AN ATTACKER DOES (2-4 sentences, names API calls),
  HOW TO FIX (copy-pasteable CLI/JSON, <PLACEHOLDER> for values).
- Caching strategy: template the most common, narratively-generic
  findings instead of calling the API for every single one — the
  blueprint's own estimate is 50-70% cost reduction. Only call the API
  for findings whose blast-radius reasoning genuinely differs instance
  to instance (which role got chained to, which account is external,
  which specific action root performed).

anthropic.Anthropic()'s init and messages.create()'s parameters
(model, system, messages, max_tokens) were confirmed against the
installed SDK before writing this, not assumed.
"""

import re
from dataclasses import dataclass

from plexavo.findings import Finding

# `anthropic` is an optional extra (`pip install plexavo[ai]`) — imported
# lazily, inside explain_finding()'s API branch, so the 90%+ of OSS users
# who never set ANTHROPIC_API_KEY never need it installed at all.

MODEL = "claude-sonnet-5"

SYSTEM_PROMPT = """You are a cloud security analyst writing a finding \
for a startup CTO who understands their product but has never done a \
security audit.

Rules:
- No jargon without immediate explanation
- Every attack description must name specific AWS API calls
- Every fix must be a copy-pasteable CLI command or policy JSON
- If the finding enables a chain to other resources, name those resources
- Be direct. No "it is recommended that..." — say "Fix this by..."
- The fix must be fully self-contained: only native AWS CLI commands, \
console steps, or IAM policy JSON. Never recommend installing or \
running any third-party tool, scanner, or product (open-source or \
commercial) as part of the fix.
"""

USER_PROMPT_TEMPLATE = """Finding type: {check_id}
Severity: {severity}
Resource: {resource_arn}
Detail: {raw_detail}
Account context: {account_context}

Write exactly three sections:

WHAT'S WRONG: One sentence. What is misconfigured and why it matters.

WHAT AN ATTACKER DOES: The specific steps an attacker takes to exploit \
this, naming AWS API calls (e.g., "calls sts:AssumeRole to become \
role X, then calls s3:GetObject to download customer data from \
bucket Y"). 2-4 sentences maximum.

HOW TO FIX: The exact AWS CLI command or IAM policy JSON to fix this. \
Must be copy-pasteable. If it requires replacing a value, use \
<PLACEHOLDER> syntax."""


@dataclass
class Explanation:
    whats_wrong: str
    attacker_does: str
    how_to_fix: str
    source: str  # "template" | "api" | "api-unparsed" | "fallback" — for cost/quality auditing

    def full_text(self) -> str:
        return (f"WHAT'S WRONG: {self.whats_wrong}\n\n"
                f"WHAT AN ATTACKER DOES: {self.attacker_does}\n\n"
                f"HOW TO FIX: {self.how_to_fix}")


def _short_name(resource_arn: str) -> str:
    """Extract a readable identifier from an ARN or bare resource ID."""
    if "/" in resource_arn:
        return resource_arn.rsplit("/", 1)[-1]
    if ":" in resource_arn:
        return resource_arn.rsplit(":", 1)[-1]
    return resource_arn


_SECTION_HEADERS = ["WHAT'S WRONG", "WHAT AN ATTACKER DOES", "HOW TO FIX"]


def _strip_stray_markdown_headers(text: str) -> str:
    """Remove leftover bare markdown heading-marker lines (a line that's
    only '#' characters, with nothing else) anywhere in the text — can
    end up orphaned mid-content by the header-splitting regex below."""
    cleaned_lines = [
        ln for ln in text.split("\n")
        if not (ln.strip() and set(ln.strip()) <= {"#"})
    ]
    result = "\n".join(cleaned_lines)
    return re.sub(r"\n{3,}", "\n\n", result).strip()


def _strip_leading_markdown_noise(text: str) -> str:
    """Strip leftover markdown noise (#, *, :, whitespace) from the
    START of extracted section content only — never touches formatting
    later in the text, so it can't corrupt intentional bold/lists
    deeper in a real answer. This handles whatever ORDER Claude happened
    to put colon/asterisks/hashes in around a header — three different
    orderings showed up across three real API calls, and special-casing
    each one individually in the split regex doesn't scale; stripping
    any run of that noise from the leading edge, regardless of order,
    does. Applied after _strip_stray_markdown_headers, which catches
    orphaned bare-# lines that land mid-content instead of at the start."""
    return re.sub(r"^[\s:#*]+", "", text).strip()


def _parse_sections(raw_text: str) -> tuple[str, str, str]:
    """Parse Claude's 3-section output. Tolerant of markdown bold
    markers, markdown heading markers (#, ##, ###), missing colons, and
    case variation, since LLM output formatting isn't perfectly
    deterministic call to call. If no headers are found at all, returns
    the full raw text in whats_wrong rather than silently dropping
    content — losing a finding's explanation entirely would be worse
    than one slightly-misplaced field."""
    header_pattern = r"#{0,3}\s*\*{0,2}(" + "|".join(re.escape(h) for h in _SECTION_HEADERS) + r")\*{0,2}:?"
    parts = re.split(header_pattern, raw_text, flags=re.IGNORECASE)
    sections = {}
    i = 1
    while i < len(parts) - 1:
        header = parts[i].strip().upper()
        content = _strip_leading_markdown_noise(_strip_stray_markdown_headers(parts[i + 1]))
        sections[header] = content
        i += 2
    whats_wrong = sections.get("WHAT'S WRONG", "")
    attacker_does = sections.get("WHAT AN ATTACKER DOES", "")
    how_to_fix = sections.get("HOW TO FIX", "")
    if not (whats_wrong or attacker_does or how_to_fix):
        return (_strip_leading_markdown_noise(_strip_stray_markdown_headers(raw_text)), "", "")
    return whats_wrong, attacker_does, how_to_fix


# ---------------------------------------------------------------------------
# Templates for the 10 most common, narratively-generic check types.
# Every specific fact (resource names, chain targets) already lives in
# the Finding's own fields, computed deterministically in Python — the
# template just substitutes them into fixed prose matching the same
# voice/rules as the system prompt, with zero API cost.
# ---------------------------------------------------------------------------

def _template_iam01(f: Finding) -> Explanation:
    name = _short_name(f.resource_arn)
    return Explanation(
        whats_wrong=f"'{name}' has a policy granting Action:* on Resource:* — full administrator access with no restriction.",
        attacker_does=(
            "Anyone who obtains this identity's credentials (a leaked access key, a phished session, a "
            "compromised machine it's used on) can call ANY AWS API — create new admin users via "
            "iam:CreateUser plus iam:AttachUserPolicy, read every S3 bucket via s3:GetObject, or delete "
            "CloudTrail logs via cloudtrail:DeleteTrail to cover their tracks."
        ),
        how_to_fix=(
            "Replace the wildcard policy with the minimum permissions this identity actually uses:\n"
            "aws iam detach-user-policy --user-name <PLACEHOLDER> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess\n"
            "Then attach a scoped policy covering only what it needs."
        ),
        source="template",
    )


def _template_iam06(f: Finding) -> Explanation:
    name = _short_name(f.resource_arn)
    return Explanation(
        whats_wrong=f"'{name}' can call sts:AssumeRole on any role in the account, including admin roles created after this scan.",
        attacker_does=(
            "An attacker with this identity's credentials calls sts:AssumeRole against any role ARN they "
            "choose — including ones they create themselves if another permission allows it — instantly "
            "gaining whatever that role can do, with no need to know in advance which roles exist."
        ),
        how_to_fix=(
            "Scope sts:AssumeRole to specific role ARNs instead of Resource:*. Edit the policy statement's "
            'Resource field, e.g.:\n"Resource": ["arn:aws:iam::<ACCOUNT_ID>:role/<PLACEHOLDER-ROLE-NAME>"]'
        ),
        source="template",
    )


def _template_iam09(f: Finding) -> Explanation:
    name = _short_name(f.resource_arn)
    return Explanation(
        whats_wrong=f"'{name}' has console (password) access enabled but hasn't logged in for 90+ days.",
        attacker_does=(
            "A dormant credential is one nobody's watching. If the password was ever weak, reused, or "
            "phished, an attacker can log in via signin.amazonaws.com as this user and nobody notices, "
            "because nobody expects this account to be active."
        ),
        how_to_fix=(
            "If console access genuinely isn't needed anymore:\n"
            "aws iam delete-login-profile --user-name <PLACEHOLDER>\n"
            "If it is, have the user log in and rotate the password, or migrate to IAM Identity Center (SSO) instead."
        ),
        source="template",
    )


def _template_iam10(f: Finding) -> Explanation:
    name = _short_name(f.resource_arn)
    return Explanation(
        whats_wrong=f"'{name}' has an access key older than the recommended rotation window.",
        attacker_does=(
            "The longer a static key lives, the more chances it's had to leak — committed to a public repo, "
            "logged in plaintext, synced to a personal device. An attacker who finds an old key confirms it's "
            "live with sts:GetCallerIdentity, then acts as this identity indefinitely until someone notices."
        ),
        how_to_fix=(
            "Create a new key, update whatever uses the old one, then deactivate it (not delete, in case "
            "something still depends on it):\n"
            "aws iam create-access-key --user-name <PLACEHOLDER>\n"
            "aws iam update-access-key --user-name <PLACEHOLDER> --access-key-id <OLD_KEY_ID> --status Inactive"
        ),
        source="template",
    )


def _template_iam11(f: Finding) -> Explanation:
    name = _short_name(f.resource_arn)
    return Explanation(
        whats_wrong=f"'{name}' has more than one active access key at the same time.",
        attacker_does=(
            "A second active key is often a forgotten one, created for a one-off task and never deactivated. "
            "Every active key is a separate way in — an attacker only needs to compromise the forgotten one, "
            "not the one you're actively watching."
        ),
        how_to_fix=(
            "Confirm which key is genuinely still in use, then deactivate the other:\n"
            "aws iam list-access-keys --user-name <PLACEHOLDER>\n"
            "aws iam get-access-key-last-used --access-key-id <KEY_ID>\n"
            "aws iam update-access-key --user-name <PLACEHOLDER> --access-key-id <UNUSED_KEY_ID> --status Inactive"
        ),
        source="template",
    )


def _template_iam13(f: Finding) -> Explanation:
    return Explanation(
        whats_wrong="The root account has no MFA device enabled.",
        attacker_does=(
            "Root can't be permission-limited — it can do anything in this account, including things no IAM "
            "policy can block. If the root password alone is ever guessed, phished, or leaked, that's the "
            "entire account, no second factor required."
        ),
        how_to_fix=(
            "Sign in to the AWS console as root, go to IAM > Security credentials > Assign MFA device, and "
            "add a hardware key or authenticator app. This can't be done via CLI — it requires the root console session."
        ),
        source="template",
    )


def _template_net01(f: Finding) -> Explanation:
    name = _short_name(f.resource_arn)
    return Explanation(
        whats_wrong=f"Instance '{name}' has an admin port (SSH/RDP) open to the entire internet (0.0.0.0/0).",
        attacker_does=(
            "Automated scanners probe every public IP for open port 22/3389 within minutes of it appearing. "
            "An attacker who finds it attempts credential brute-forcing or exploits any unpatched SSH/RDP "
            "vulnerability directly, with nothing else to compromise first."
        ),
        how_to_fix=(
            "Restrict the security group rule to your specific IP instead of 0.0.0.0/0:\n"
            "aws ec2 revoke-security-group-ingress --group-id <PLACEHOLDER-SG-ID> --protocol tcp --port 22 --cidr 0.0.0.0/0\n"
            "aws ec2 authorize-security-group-ingress --group-id <PLACEHOLDER-SG-ID> --protocol tcp --port 22 --cidr <YOUR_IP>/32"
        ),
        source="template",
    )


def _template_net02(f: Finding) -> Explanation:
    name = _short_name(f.resource_arn)
    return Explanation(
        whats_wrong=f"Instance '{name}' has a database port open to the entire internet (0.0.0.0/0).",
        attacker_does=(
            "An attacker connects directly to the database port from anywhere and attempts default "
            "credentials or known vulnerabilities for that engine — no need to compromise the application "
            "in front of it, since the database itself is directly reachable."
        ),
        how_to_fix=(
            "Remove the public rule and scope it to only the application servers that need it, referencing "
            "their security group instead of an open CIDR:\n"
            "aws ec2 revoke-security-group-ingress --group-id <PLACEHOLDER-SG-ID> --protocol tcp --port <PORT> --cidr 0.0.0.0/0\n"
            "aws ec2 authorize-security-group-ingress --group-id <PLACEHOLDER-SG-ID> --protocol tcp --port <PORT> --source-group <APP_SG_ID>"
        ),
        source="template",
    )


def _template_stor19(f: Finding) -> Explanation:
    name = _short_name(f.resource_arn)
    return Explanation(
        whats_wrong=f"Bucket '{name}' doesn't have full S3 Block Public Access protection enabled.",
        attacker_does=(
            "Without this protection, a single mistake — an overly broad bucket policy, a public ACL grant, "
            "someone copy-pasting a policy from a tutorial — immediately exposes every object to anyone on "
            "the internet via a plain s3:GetObject call, with nothing left to catch the mistake."
        ),
        how_to_fix=(
            "Enable all four Block Public Access settings unless there's a specific, documented reason not to:\n"
            f'aws s3api put-public-access-block --bucket {name} --public-access-block-configuration '
            '"BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"'
        ),
        source="template",
    )


def _template_enc29(f: Finding) -> Explanation:
    name = _short_name(f.resource_arn)
    return Explanation(
        whats_wrong=f"EBS volume '{name}' is not encrypted at rest.",
        attacker_does=(
            "If this volume's underlying storage is ever exposed — a misconfigured snapshot shared publicly, "
            "physical disk decommissioning at AWS's end — the data on it is readable in plaintext, no "
            "encryption key required."
        ),
        how_to_fix=(
            "Existing volumes can't be encrypted in place — snapshot it, copy the snapshot with encryption "
            "enabled, then create a new volume from that:\n"
            f"aws ec2 create-snapshot --volume-id {name}\n"
            "aws ec2 copy-snapshot --source-snapshot-id <SNAPSHOT_ID> --encrypted --source-region <PLACEHOLDER-REGION>\n"
            "aws ec2 create-volume --snapshot-id <ENCRYPTED_SNAPSHOT_ID> --availability-zone <PLACEHOLDER-AZ>"
        ),
        source="template",
    )


COMMON_CHECK_TEMPLATES = {
    "IAM-01": _template_iam01,
    "IAM-06": _template_iam06,
    "IAM-09": _template_iam09,
    "IAM-10": _template_iam10,
    "IAM-11": _template_iam11,
    "IAM-13": _template_iam13,
    "NET-01": _template_net01,
    "NET-02": _template_net02,
    "STOR-19": _template_stor19,
    "ENC-29": _template_enc29,
}


def explain_finding(finding: Finding, client=None) -> Explanation:
    """Route to a templated explanation (zero API cost) for the 10 most
    common, narratively-generic check types, or call Claude for findings
    where account-specific chain/blast-radius reasoning genuinely varies
    (which role got chained to, which account is external, which
    specific root action fired, etc.).

    `client` is accepted for testability (inject a fake Anthropic client
    to prove the templated path never touches the network, or to test
    the API path without spending real tokens). Production code never
    needs to pass this — it's built automatically from ANTHROPIC_API_KEY.

    Deliberately broad exception handling: an AI explanation is
    enrichment on top of an already-valid, already-computed finding —
    not the thing that makes the finding true. A failed API call must
    never crash the scan or lose the underlying finding, unlike the
    strict fail-fast handling used everywhere else in this project for
    actual AWS state (where silently swallowing an unexpected error
    could hide a real detection bug).
    """
    template_fn = COMMON_CHECK_TEMPLATES.get(finding.check_id)
    if template_fn:
        return template_fn(finding)

    try:
        if client is None:
            import anthropic  # optional extra — see module docstring
            client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from env
        user_prompt = USER_PROMPT_TEMPLATE.format(
            check_id=finding.check_id,
            severity=finding.severity.value,
            resource_arn=finding.resource_arn,
            raw_detail=finding.raw_detail,
            account_context=finding.account_context,
        )
        response = client.messages.create(
            model=MODEL,
            max_tokens=2048,  # raised again — 1024 still truncated on a
            # finding whose correct fix genuinely needs 2 steps, 3
            # separate bash blocks, and an embedded JSON trust policy.
            # Cost impact is trivial even at this ceiling (worst case
            # ~$0.02/call at current output pricing), so going straight
            # to a generous number instead of nudging up again
            system=SYSTEM_PROMPT,
            thinking={"type": "disabled"},
            messages=[{"role": "user", "content": user_prompt}],
        )
        raw_text = "".join(
            block.text for block in response.content
            if getattr(block, "type", None) == "text"
        )
        if response.stop_reason == "max_tokens":
            # Don't silently return truncated content — a cut-off fix
            # command is actively dangerous (a partial CLI command is
            # worse than none), so this must be visible, not swallowed.
            raw_text += "\n\n[TRUNCATED: response hit the token limit before finishing. Re-run or raise max_tokens further.]"
        whats_wrong, attacker_does, how_to_fix = _parse_sections(raw_text)
        if not (attacker_does or how_to_fix):
            return Explanation(whats_wrong, "", "", source="api-unparsed")
        return Explanation(whats_wrong, attacker_does, how_to_fix, source="api")
    except Exception:
        # Silent by design (per the OSS plan's §3.3 contract): the report
        # itself must never show a raw exception string — a missing key,
        # an invalid key, a rate limit, and a network blip all produce
        # the exact same clean output as "AI narration was never
        # attempted." The caller (cli.py) is responsible for surfacing a
        # single console-level summary if any findings fell back, using
        # the count of source=="fallback" results — not this field.
        return Explanation(
            whats_wrong=finding.raw_detail,
            attacker_does="",
            how_to_fix="",
            source="fallback",
        )
