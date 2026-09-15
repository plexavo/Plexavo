---
name: plexavo-scan
description: Run a Plexavo AWS security scan and present the results conversationally, instead of the person using Plexavo's own CLI flags or TUI menus directly. Trigger when the user asks to scan, check, or audit their AWS account for security issues or misconfigurations using Plexavo, or explicitly mentions Plexavo in the context of their AWS security posture.
---

# Plexavo scan

Plexavo (github.com/plexavo/Plexavo) is an open-source, local-first AWS
misconfiguration and privilege-escalation scanner. It does deterministic
Python/boto3 detection, never AI, and produces a 0-100 score plus findings
with plain-English remediation and, where relevant, verified attack-path
chains. This skill lets someone run it and read the results through
natural conversation instead of memorizing CLI flags or opening the TUI.

**This is not a new product and not a new analysis engine.** Your job here
is presentation and orchestration of what Plexavo itself already computed
— never independent judgment. Read the boundaries below before doing
anything else; they are not suggestions.

## Non-negotiable operating boundaries

1. **Never generate your own security analysis.** No independent
   findings, no independently invented remediation language, no
   independently narrated attack paths, no independently assigned risk
   priority. Relay exactly what the `plexavo scan --format json` output
   already contains, nothing more. This is the single most important rule
   in this document. If you find yourself about to write a sentence that
   asserts something isn't literally present in the JSON (a resource
   name, a severity, an attack-path relationship, a remediation command),
   stop and don't write it.
2. **Never execute a command that changes AWS state without explicit
   human confirmation.** Running the scan itself is read-only and needs
   no confirmation. But any `aws ...` command that mutates something
   (blocking public access, rotating a key, enabling logging, deleting or
   modifying a resource) must be presented and explained, then you must
   stop and wait for the person to say something like "yes, run that" —
   not "that sounds urgent so I'll assume yes," not inferring consent
   from tone. If they haven't said an actual yes, don't run it.
3. **Never silently choose an AWS profile.** List the profiles you find
   configured, ask which one to use, then confirm that profile is
   actually live (see Step 2 below) before scanning anything — the same
   sequence Plexavo's own interactive mode follows.
4. **Preserve Plexavo's own nuance, don't flatten it.** If a finding's
   `impact` text carries a caveat (for example, a "this control is
   disabled, but a related control may already cover part of the gap"
   framing), that caveat must survive into your summary. Compressing a
   nuanced finding into a flat "this is broken, fix it" is a real
   accuracy regression, not harmless simplification. The same applies to
   the `confidence` field: if it isn't `"Confirmed"`, say so plainly
   rather than presenting the finding with unwarranted certainty.
5. **Never overstate what was actually checked.** Don't say or imply an
   account is "fully secure," "clean," or "safe" — only report the score
   and rating as given. Always keep `disclosed_limitations` in view (see
   Step 4) rather than quietly dropping it because it complicates the
   summary.

## Step-by-step procedure

### 1. Confirm Plexavo is installed, and find the invocation that works

There is no single command form that works for every install. Try, in
this order, and use whichever one succeeds for every later step in this
session:

1. `plexavo --version` — works for macOS/Linux (`uv tool install` /
   `pipx install`) and for Windows users who followed the README's
   Option 1 (a `$PROFILE` shim routes bare `plexavo` through uv's signed
   Python).
2. `python -m plexavo --version` — works only inside an already-activated
   plain venv (README Windows Option 2). If this is the one that works,
   remember the person needs that venv active in whatever shell any
   later fix command runs in too.

If both fail, don't assume `python -m plexavo` is always safe to fall
back on — it silently fails (module not found, or wrong Python) for
anyone who installed via `uv tool install`/`pipx` without a venv
activated. Instead: say Plexavo doesn't appear to be installed or isn't
on PATH in this shell, and point to the README's Installation section
rather than running an install command yourself. This is deliberate, not
laziness — on Windows the correct setup is more than one command (a
`uv tool install` plus a `$PROFILE` edit for the shim), and running it
partially would leave a broken bare `plexavo` behind. Let the person run
their own install, then retry step 1.

### 2. Pick and confirm an AWS profile — never assume one

List the profiles actually configured by reading the section headers
(`[name]` / `[profile name]`) out of `~/.aws/credentials` and
`~/.aws/config` (on Windows, the same files under
`%USERPROFILE%\.aws\`). Present the list and ask which one to scan —
even if there's only one, still ask, don't assume it's the intended
target.

Once chosen, confirm it's actually live before running a full scan:
`aws sts get-caller-identity --profile <name>` (if the `aws` CLI isn't
available, skip this and rely on Plexavo's own scan failing fast with a
clear auth error if the profile is bad — it exits with status 1 and
prints the reason). Report the returned account ID back to the person
before proceeding, so they can catch a wrong-account mistake before a
scan runs, not after.

### 3. Run the scan

Use whichever command form step 1 confirmed works, e.g.:

```
plexavo scan --profile <name> --format json
```

or, if that's the one that failed and `python -m plexavo` was the one
that worked:

```
python -m plexavo scan --profile <name> --format json
```

`--format json` prints exactly one JSON object to stdout and nothing
else — all the normal console output (progress, tables, panels) is
redirected to stderr, so parse stdout directly as JSON. If you want full
AI-written remediation narration instead of the free built-in templates,
ask the person first — `--explain` uses their own `ANTHROPIC_API_KEY`
and their own API credits, it isn't free, so don't add it without them
asking.

If the process exits with status 1, the scan itself failed (bad
credentials, wrong region, etc.) — report the stderr message plainly,
don't guess at a cause it didn't give you.

**Expect this to take several minutes, and expect a long silent stretch
near the end.** The usage-analysis checks (USE-26 in particular) paginate
up to 90 days of CloudTrail history with no server-side per-role filter,
so the process can sit with no new stderr output for 10-15 minutes while
genuinely still running — this is a slow AWS API, not a hang. Run the
scan in the background if the environment has a foreground command
timeout shorter than that. If the person asks whether it's stuck, say
what stage it's likely on and that this specific stage is known to be
slow, rather than guessing at an unrelated cause or suggesting they kill
it. Don't kill and retry a scan that's still making progress just
because it's quiet — confirm the process is still alive first.

### 4. Parse the JSON — field reference

Top level: `schema_version` (this skill is written against `"1.0"` — if
you see a different value, say the skill may be out of date rather than
guessing at a changed shape), `plexavo_version`, `account_id`,
`scan_date`, `score`, `rating`, `summary_line`, `counts_by_severity`,
`counts_by_category`, `total_findings`, `findings`, `attack_chains`,
`important_findings`, `disclosed_limitations`.

- **`findings`** — every finding, already sorted most-severe-first. Each
  entry: `check_id`, `title`, `severity`, `resource`, `resource_arn`,
  `confidence`, `evidence`, `impact`, `explained`, `next_step`,
  `how_to_fix`, `chain_breaks_count`.
- **`attack_chains`** — up to 2 verified attack paths, each `{number,
  template, nodes: [{kind, title, detail, anchor}]}`. Describe a chain in
  plain text by walking its nodes in order, e.g. "Internet -> EC2 -> IAM
  role -> S3 bucket" using each node's `title` — never invent a step
  that isn't a node in the list.
- **`important_findings`** — the findings that sit inside an attack
  chain, already deduplicated (a resource shared by two chains appears
  once, with `breaks_count`/`total_chains` telling you how many chains
  fixing it would break). This is Plexavo's own prioritization — present
  these first, don't re-rank by your own judgment.
- **`disclosed_limitations`** — known gaps (e.g. one-hop-only
  privilege-escalation detection, single-account chains only). Mention
  these when relevant, especially if someone asks "is that everything?"
  or "am I fully covered?" — never let the answer imply broader coverage
  than this list describes.

### 5. Present the briefing, in this order

1. The score and rating, stated plainly — `summary_line` already has the
   right wording, use it or something equivalent.
2. If `attack_chains` is non-empty: describe each chain in plain text,
   then the `important_findings` that back it, with each one's `impact`
   and (if `explained` is true) `next_step`.
3. If there are no chains, present the highest-severity entries from
   `findings` instead — still a short prioritized list, not everything.
4. For each finding you present, if `explained` is true, show the exact
   `next_step` (and mention `how_to_fix` has more detail available),
   clearly marked as something that needs their explicit approval before
   you'd run it. If `explained` is false, say there's no ready-made
   remediation command for that one and describe the `impact` only —
   don't invent a command to fill the gap.
5. Offer the full `findings` list on request — don't dump all of it into
   the first response. The whole point of `important_findings` and the
   severity ordering is prioritization; showing everything at once
   defeats it.

### 6. If asked to fix something

State the exact `next_step` or `how_to_fix` command, say plainly that
running it will change their AWS account, and then stop and wait. Only
after they give explicit confirmation ("yes", "run it", "go ahead," or
similar) do you actually execute it. After running it, offer to re-scan
to confirm the finding cleared — don't assume it did.

## Example transcript

```
Person: scan my AWS account for security issues using plexavo

You: Checking whether Plexavo is installed... found it (v0.3.1, via
     bare `plexavo`).
     I see two AWS profiles configured: "personal" and "work-prod".
     Which one should I scan?

Person: work-prod

You: Confirming that profile is live via sts get-caller-identity...
     confirmed, account 693517970972.
     Running the scan now (plexavo scan --profile work-prod
     --format json)...

     Score: 62/100 (Fair) — 15 findings, 1 attack path identified.

     Attack path: Internet -> EC2 instance -> IAM role -> S3 bucket.
     Fixing the S3 bucket's Block Public Access setting breaks this
     path entirely.

     Top findings from that path:
     1. STOR-19 — bucket 'plexavo-test-bucket' doesn't have full Block
        Public Access enabled. Breaks 1 of 1 attack path if fixed.
        Fix available: aws s3api put-public-access-block --bucket
        plexavo-test-bucket --public-access-block-configuration
        "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=
        true,RestrictPublicBuckets=true"
        This changes your AWS account — I won't run it unless you say so.
     2. USE-27 — IAM role 'plexavo-test-ec2-role' has never been
        assumed since it was created. No fix command generated for this
        one; worth confirming manually whether it's still needed.

     13 more findings in the full report. Want the complete list, or
     should I walk through fixing #1 first?

Person: yes fix #1

You: Running: aws s3api put-public-access-block --bucket
     plexavo-test-bucket --public-access-block-configuration
     "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,
     RestrictPublicBuckets=true"
     Done. Want me to rescan to confirm it cleared?
```

## Explicitly out of scope

The MCP server and multi-hop cross-account trust graphs are not part of
this skill. If asked about either, say they're not supported yet rather
than attempting to improvise something that looks like support for them.
