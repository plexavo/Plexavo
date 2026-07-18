# Technical Explainer

How this scanner actually works, end to end — architecture, mechanisms,
real design decisions, and the real bugs that shaped them. Written for
anyone who wants to understand or extend the codebase, not just use it.

## Architecture, in one picture

```
IAM enumeration → 31 deterministic checks → Finding objects → scoring
                                                    │
                                                    ▼
                                    explainer.py (AI narration, opt-in)
                                                    │
                                                    ▼
                                    report/ (HTML via Jinja2, PDF via fpdf2)
```

Cross-account access (getting permission to scan someone else's account)
is a separate, upstream concern handled by `cfn/` — covered at the end.

The core principle: **detection is never AI.** Every finding is produced
by deterministic Python reading real AWS API responses. Claude's only
job, and only when `--explain` is passed, is rewriting an
already-decided, already-true finding into plain English. If the AI
layer failed entirely, every check would still work identically — it
would just print `raw_detail` instead of a 3-section narrative.

## 1. Detection layer

### The Finding model

`scanner/findings.py` defines `Finding` (check_id, title, severity,
resource_arn, raw_detail, account_context) and `Severity`
(Critical/High/Medium/Low), each carrying a `score_penalty` (15/8/3/1)
used directly by `scoring.py`.

### Principal enumeration

`scanner/principals.py`'s `list_all_principals()` is the shared
foundation most IAM-related checks build on: it walks every IAM user
and role, resolves their attached managed policies, inline policies,
and **group-inherited policies** (a real bug fixed early — a user's
group memberships were initially invisible to the scanner), and
normalizes each policy statement's `Action`/`Resource`/`NotAction`
fields into consistent lists regardless of whether AWS returned a
string or an array.

Two non-obvious things this layer gets right, because getting them
wrong silently under- or over-reports risk:
- **Explicit Deny statements suppress findings** — `find_blocking_deny()`
  checks for an unconditional Deny before flagging a wildcard grant.
  A conditional Deny downgrades severity rather than suppressing
  entirely.
- **Permission boundaries** are fetched per-principal (`get_role`/
  `get_user`, not just the paginated list response, which doesn't
  reliably include them) and applied to every check, not just the ones
  that reference boundaries directly.

### The 6 check categories

Each category is one file under `scanner/checks/`, each exposing a
`run_all(session, ...)` that returns a `list[Finding]`. A few
categories needed real, non-obvious AWS mechanics to get right:

**IAM hygiene (`iam_hygiene.py`)** — IAM-09/10's "dormant N+ days"
checks take a `threshold_days` parameter specifically so they can be
validated against real AWS data *without waiting N real days*: run the
same comparison logic at `threshold_days=0` against a fresh resource
(should fire) and `threshold_days=9999` (should stay silent). This
threshold trick recurs throughout the project wherever a check depends
on elapsed time.

**Network (`network.py`)** — cross-references security group rules
against which EC2/RDS resources actually use them, so an open port on
an *orphaned* security group (attached to nothing) doesn't produce a
false positive.

**Storage (`storage.py`)** — S3's error-handling here is a deliberate,
verified pattern: `NoSuchBucketPolicy` and
`NoSuchPublicAccessBlockConfiguration` are **not modeled as distinct
exception classes** in S3's real service model (confirmed by inspecting
`botocore`'s service model directly, not assumed) — the naive
`except s3.exceptions.NoSuchX` pattern that works for IAM silently
never matches for S3, and either crashes (if the code path is hit) or
sits as a latent bug (if it isn't). Every S3 error-branch in this
project uses generic `except ClientError as e: if e.response["Error"]
["Code"] != "X": raise` instead.

**Logging (`logging.py`)** — LOG-22/LOG-23 are account-wide, not
per-trail (`any(trail is good for trail in trails)`), which has a real
structural consequence: once a real, healthy trail exists in an
account, no amount of additional test trails can prove the "should
fire" case, since the real trail alone always satisfies the `any()`.
The only way to prove this is a second, genuinely untouched AWS
account — see `docs/LOGGING-TEST-MATRIX.md` for how that was done (the
one-off script used isn't part of this public repo — see that file for
why).

**Usage analysis (`usage.py`)** — the hardest category, built last on
purpose. Two real mechanics worth knowing:
- CloudTrail's `LookupEvents` has **no server-side filter for "events
  performed by this role."** The `Username` attribute matches the
  assumed-role *session* name (arbitrary, unknowable in advance), not
  the role name. Usage is built by fetching CloudTrail broadly once and
  attributing each event to a role client-side via
  `userIdentity.sessionContext.sessionIssuer.arn`.
- **IAM permission names and CloudTrail event names aren't always the
  same string.** Confirmed via a real live bug: `s3:ListAllMyBuckets`
  is the IAM permission; CloudTrail records the call as `ListBuckets`
  — no "AllMy". `_IAM_TO_CLOUDTRAIL_EVENTNAME_EXCEPTIONS` in
  `usage.py` is an explicitly non-exhaustive map of confirmed cases,
  not a claim of complete coverage.

### Ground truth methodology

Every check has a matching `terraform-testbed/*.tf` file seeding real
AWS misconfigurations, graded against a `*-TEST-MATRIX.md`. The
discipline: **a check isn't "done" until it's proven both directions**
— fires on the bad case, stays silent on a deliberately clean/scoped
equivalent — against real AWS, not just offline mocks. A handful of
checks have a stated, permanent exception to this (documented per-check
in their matrix file) where the "bad" state is either physically
impossible to construct (e.g. ENC-31 — AWS made S3 default encryption
mandatory in 2023, so "no encryption" can't exist on a bucket created
today) or would require compromising a real security control to test
(e.g. disabling real root MFA).

## 2. Scoring

`scoring.py`: start at 100, subtract `severity.score_penalty` per
finding, floor at 0. Rating bands (Excellent/Good/Fair/Poor/Critical)
are calibrated against the one worked example the original spec
provided ("34/100 (Poor)"), verified as an exact test case, not just a
plausible-looking threshold.

## 3. AI narration (`scanner/explainer.py`)

### Cost control: templates vs. API

10 of the most common, narratively-generic finding types
(`COMMON_CHECK_TEMPLATES`) are hand-written Python f-strings —
zero API cost, zero latency. Everything else calls Claude
(`claude-sonnet-5`). This is the blueprint's own stated cost strategy,
not an afterthought.

### Real bugs found via live output, not anticipated in advance

This module went through several rounds of "looks right in tests, then
breaks on real output" — worth documenting because each one represents
a real class of bug, not a typo:

1. **`ThinkingBlock` has no `.text` attribute.** Sonnet 5 has adaptive
   thinking on by default for any request that doesn't explicitly
   disable it — `response.content[0]` isn't reliably the text block.
   Fixed by disabling thinking (`{"type": "disabled"}`, unnecessary for
   a rewrite task) and filtering `response.content` by `block.type ==
   "text"` instead of assuming position.
2. **Markdown noise leaking through as literal characters** across
   three separate real API responses, in three different orderings
   (`**text:`, `## text:`, `text:**`). Fixed by giving up on matching
   every specific ordering and instead stripping any leading noise
   (`#`, `*`, `:`, whitespace) generically.
3. **fpdf2's underline marker is literally `--`.** Untested, this would
   have silently deleted the `--` from every AWS CLI flag
   (`--user-name` → `user-name`) in every generated PDF, breaking every
   copy-pasteable command. Caught by testing the specific interaction
   directly before shipping, not discovered after the fact.
4. **Asterisk collision in IAM wildcards.** Converting inline code
   (`` `*:*` ``) to bold (`**`) for the PDF collided with the *content's
   own* literal asterisks — genuinely common subject matter for a
   security scanner — producing `***:***`. Switched to italics (`__`)
   for PDF inline-code approximation instead, since double-underscores
   essentially never appear in AWS/CLI vocabulary.
5. **The model recommended competing open-source tools** (PMapper,
   `aws_escalate`) inside a `HOW TO FIX` section. Not a formatting bug
   — a product-positioning one. Fixed by adding an explicit system
   prompt constraint: fixes must be self-contained AWS actions, never a
   pointer to a third-party tool.

## 4. Report generation (`report/`)

`generator.py`'s `build_report_data()` is the single source of truth
both outputs render from — HTML and PDF can't silently drift into
different content, only different presentation.

- **HTML** (`generate_html`): Jinja2, with a custom `markdown_inline`
  filter that safely converts `**bold**`/`` `code` `` into real
  `<strong>`/`<code>` tags (escaping first, then inserting only HTML
  the filter itself produces — never trusting the AI's raw output as
  safe HTML).
- **PDF** (`pdf.py`): fpdf2, not WeasyPrint. WeasyPrint was the
  original spec's first choice; switched after confirming (via current
  documentation, not assumption) that its GTK/Pango/Cairo native
  dependencies are a well-documented, still-current source of
  multi-hour Windows installation failures. fpdf2 is pure Python, zero
  native dependencies — the original spec's own named fallback.
  - Bundles DejaVu Sans (`report/fonts/`) because fpdf2's built-in core
    fonts are Latin-1 only and **crash outright** on an em-dash —
    confirmed by direct test, not assumed, and this project's finding
    text uses em-dashes constantly.
  - `multi_cell()` defaults to **justified** alignment, not left —
    confirmed as the cause of a real visual bug (huge, uneven word
    spacing) only visible by reading actual rendered output; text
    extraction-based testing structurally cannot catch this class of
    bug, since extracted text has no concept of visual glyph spacing.
    A permanent regression test inspects the PDF's raw content stream
    for the actual spacing-adjustment values now, not just extracted
    words.

## 5. Local credential access (`plexavo/auth.py`)

The mechanism by which the scanner gets AWS access at all: the caller's
own local credentials, resolved exactly the same way the AWS CLI itself
resolves them — a named `--profile`, the default profile, or environment
variables. `boto3.Session(profile_name=...)` does this resolution
natively; `get_local_session()` wraps it with upfront, fail-fast checks
(missing profile, missing region, missing credentials) so a
misconfiguration surfaces as one clear message before any check runs,
not as a confusing permission error buried inside the sixth check that
happens to touch AWS first.

**Earlier design, dropped:** a CloudFormation-deployed cross-account IAM
role (`cfn/scanner-access-role.yaml`) with a per-recipient
`sts:ExternalId`, so a separate AWS account owner could grant this tool
read-only access without sharing real credentials — the standard pattern
for a *hosted* scanning product. That mechanism required trusting an
external operator account, which is exactly the trust barrier an
early-stage, unknown OSS tool can't clear (see the OSS release plan,
§1). It's been deleted from this codebase, not hidden — there's no
reason to carry cross-account code for a flow the CLI tool doesn't use.
It'll be rebuilt, deliberately differently, if and when a hosted
platform is actually built.

## Known, stated limitations

Not hidden — each is documented in its check's own test matrix file,
with the specific reason:

- **ENC-31** (S3 default encryption): AWS made SSE-S3 mandatory and
  irrevocable for every bucket since January 2023 — the "missing
  encryption" case this check detects can't be constructed on a bucket
  created today. The check remains correct for real accounts with
  pre-2023 buckets.
- **LOG-22/LOG-23** on the primary test account: structurally
  untestable once a real, healthy CloudTrail trail exists (see above).
  Proven instead against a genuinely untouched second AWS account.
- **IAM-08** (cross-account trust) needed a real second AWS account to
  test against — AWS's `CreateRole` validates that a trust policy's
  account-ID principal is a real, existing account, rejecting
  made-up numbers.
- **IAM-12/IAM-13** (root usage / root MFA): only the negative case can
  be proven without actually using real root credentials, which this
  project deliberately never does to manufacture a test case.
