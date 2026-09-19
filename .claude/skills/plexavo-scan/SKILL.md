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

### 1. Make sure Plexavo is installed, and find the invocation that works

If Plexavo isn't installed, you install it, with the person's permission at
every step that changes their machine. Do not just tell them to go read the
README.

**1a. Detect the platform.** Use the OS Claude Code reports (Windows, macOS,
or Linux; WSL counts as Linux). On Windows, run the commands below in
PowerShell. Two facts matter later: your shell does not load the person's
PowerShell `$PROFILE`, so the Windows `plexavo` shim (1e) is invisible to you
even when it is set up correctly for them, and that means `plexavo` not being
found in your shell does NOT prove it is missing. Try every form in 1b before
concluding it isn't installed.

**1b. Look for an existing install.** Try these in order. The first one that
prints `plexavo X.Y.Z` is the invocation to use for the rest of the session;
call it `<plexavo>` below.

1. `plexavo --version`. If it fails with "An Application Control policy has
   blocked this file", Plexavo IS installed and Windows Smart App Control is
   blocking its launcher, so go on to form 2 instead of reinstalling.
2. The tool's own Python, called directly. This works regardless of PATH,
   profile, or Smart App Control. Get the uv tool directory with
   `uv tool dir` (if `uv` isn't on PATH in your shell, try its default
   location: `~/.local/bin/uv` on macOS/Linux,
   `$env:USERPROFILE\.local\bin\uv.exe` on Windows), then run:
   - Windows: `& "<tool dir>\plexavo\Scripts\python.exe" -m plexavo --version`
   - macOS/Linux: `<tool dir>/plexavo/bin/python -m plexavo --version`
3. The fallback venv from 1f, if it exists:
   `~/.plexavo-venv/bin/python -m plexavo --version` (macOS/Linux) or
   `& "$env:USERPROFILE\.plexavo-venv\Scripts\python.exe" -m plexavo --version`
   (Windows).
4. `python -m plexavo --version`, which only works inside an already-activated
   plain venv (README Windows Option 2). If this is the one that works,
   remember the venv must be active in whatever shell any later fix command
   runs in too.

Once one works, check the version. Anything older than 0.4.0 has no
`--format json`, so this skill can't use it: say so and offer to upgrade
(`uv tool upgrade plexavo` for a uv install,
`<venv python> -m pip install --upgrade plexavo` for a venv install), with
permission. If all four forms fail, Plexavo isn't installed: go to 1c.

**1c. Install rules.** These have the same standing as the boundaries above.

- Say what you're about to install and why, show the exact command, and wait
  for an explicit yes before each step that changes their machine: installing
  uv, installing Plexavo, editing their PowerShell profile. One step at a
  time, not one blanket "install everything?".
- User-level installs only. No `sudo`, no admin rights, no `pip install`
  outside a venv, no `--break-system-packages`, no `pip install --user`. If
  a step truly needs admin (see 1f), give them the command and let them
  decide.
- Never turn off Smart App Control, SmartScreen, or antivirus, and never run
  a blocked executable to get around a block. The Windows steps below exist
  so that nothing blocked is ever run.
- If they decline a step, stop there. Don't route around it with something
  equivalent. Point them to the README's Installation section instead.
- If a command fails, show the actual error. Don't improvise a different
  install method to make it go away.

**1d. Preferred path: uv.** `uv tool install` gives Plexavo its own isolated
environment: no "externally-managed-environment" error like plain `pip` hits
on current Python, no changes to the system Python, and uv fetches a suitable
Python (3.9+) itself if the machine has none.

1. Check `uv --version` (default locations as in 1b). If uv is present, skip
   to step 3.
2. If uv is missing, explain it in plain words before asking, for example:
   "uv is Astral's official Python tool manager. I'd like to install it
   because it can set Plexavo up in its own isolated environment, which
   avoids the system-Python errors plain pip gives, and it needs no admin
   rights. It installs into `~/.local/bin`." After a yes, run the official
   installer:
   - macOS/Linux: `curl -LsSf https://astral.sh/uv/install.sh | sh` (or
     `wget -qO- https://astral.sh/uv/install.sh | sh` if there's no curl)
   - Windows:
     `powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"`

   Be upfront that this downloads and runs a script from astral.sh, the
   method uv's own docs give, and that they can open the URL and read it
   first. If they'd rather not, offer a package manager they already have
   (`brew install uv`, `winget install --id=astral-sh.uv -e`). The installer
   edits PATH for NEW terminals only, so in this session call uv by its full
   default path and confirm `--version` works before going on.
3. After a yes: `uv tool install plexavo`. If uv warns that its tool bin
   directory isn't on PATH, that's fine for this session (1b form 2 needs no
   PATH). `uv tool update-shell` would fix it for new terminals but edits
   their shell config, so offer it, don't run it unasked.
4. macOS/Linux: confirm with 1b. Windows: continue to 1e.

**1e. Windows only: make bare `plexavo` work in the person's own terminals.**
Explain it first: `uv tool install` creates an unsigned `plexavo.exe`
launcher, and Smart App Control / SmartScreen blocks it ("An Application
Control policy has blocked this file"). uv's own `python.exe` is signed, so
the fix is a small PowerShell function that routes `plexavo` through it. This
session already works via 1b form 2, so it isn't needed for the scan itself,
but it is the README's recommended setup (Option 1), so offer it. Say plainly
what it changes: their PowerShell profile, and their execution policy for the
current user only (no admin). After a yes:

1. Check `Get-ExecutionPolicy -List`. Only if CurrentUser is `Undefined` or
   `Restricted` and both MachinePolicy and UserPolicy are `Undefined`, run
   `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` (it lets their own
   local profile script load; downloaded scripts still need a signature).
   If it's already RemoteSigned, Unrestricted, or Bypass, leave it alone. If
   it's AllSigned or set by Group Policy, don't override it, tell them.
2. `if (!(Test-Path $PROFILE)) { New-Item -ItemType File -Path $PROFILE -Force }`
3. Add the function only if it isn't there already (repeated setups
   otherwise stack up duplicates):
   ```
   if (-not (Select-String -Path $PROFILE -Pattern 'function plexavo' -Quiet)) { Add-Content $PROFILE 'function plexavo { & "$env:APPDATA\uv\tools\plexavo\Scripts\python.exe" -m plexavo @args }' }
   ```
   If `uv tool dir` isn't `$env:APPDATA\uv\tools` (a custom `UV_TOOL_DIR`),
   put the real directory in that function body instead.
4. Tell them to open a NEW terminal to use bare `plexavo`. You can't verify
   it from your own shell (it doesn't load their profile), so confirm the
   install with 1b form 2.

**1f. Fallback: pip in a venv.** Only if they decline uv, or uv can't be
installed. This needs Python 3.9+ already on the machine (`python3 --version`
on macOS/Linux, `py --version` on Windows). If there is none, don't install a
system Python: say uv would supply one, or that they can install Python from
python.org, and stop. Explain why a venv: plain `pip install plexavo` outside
one fails with "externally-managed-environment" on current Python (and would
put Plexavo's dependencies into their system Python), so it goes into a
private venv at `~/.plexavo-venv`. After a yes:

- macOS/Linux:
  ```
  python3 -m venv ~/.plexavo-venv
  ~/.plexavo-venv/bin/python -m pip install plexavo
  ```
  If venv creation fails with "ensurepip is not available" (Debian/Ubuntu need
  the `python3-venv` package), that install needs `sudo`: give them the
  command, don't run it yourself.
- Windows:
  ```
  py -m venv "$env:USERPROFILE\.plexavo-venv"
  & "$env:USERPROFILE\.plexavo-venv\Scripts\python.exe" -m pip install plexavo
  ```
  Use `python -m pip` and `python -m plexavo` for everything here: the venv's
  own `pip.exe` and `plexavo.exe` are unsigned launchers Smart App Control
  blocks, and only its `python.exe` is signed. There's no profile shim for
  this path; you call the venv's Python directly (1b form 3).

**1g. Confirm.** Run the `--version` check with the form you'll use, tell the
person the version and which form it is, then go on to step 2. If the install
failed or they declined, stop here: don't scan, and point them to the
README's Installation section.

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

Use the `<plexavo>` form step 1 confirmed, exactly as it was confirmed:

```
<plexavo> scan --profile <name> --format json
```

For example `plexavo scan ...`, or `python -m plexavo scan ...`, or, for the
direct forms, `& "<tool dir>\plexavo\Scripts\python.exe" -m plexavo scan ...`
on Windows / `<tool dir>/plexavo/bin/python -m plexavo scan ...` on
macOS/Linux.

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

You: Checking whether Plexavo is installed... found it (v0.4.1, via
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

Same skill on a Windows machine with nothing installed (each step waits for
a yes before anything on the machine changes):

```
Person: scan my AWS account for security issues using plexavo

You: Checking for Plexavo... `plexavo` isn't found, and it isn't in uv's
     tool folder either, so it isn't installed. I also don't see `uv`.
     I can set this up, one step at a time, and I'll ask before each one.
     Step 1: install uv, Astral's official Python tool manager. I want it
     because it puts Plexavo in its own isolated environment (no system
     Python changes, no "externally-managed-environment" errors) and needs
     no admin rights. It runs Astral's installer from astral.sh:
       powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
     Okay to install uv?

Person: yes

You: Installed uv 0.12.5 (in %USERPROFILE%\.local\bin). Step 2: run
     `uv tool install plexavo` to install Plexavo itself. Okay?

Person: yes

You: Installed plexavo 0.4.1. One Windows-specific thing: uv's plexavo.exe
     launcher is unsigned, so Smart App Control blocks it when you type
     `plexavo` in your own terminal. Step 3 (optional, for your own
     terminals; I can already run Plexavo directly through uv's signed
     Python for this scan): add a `plexavo` function to your PowerShell
     profile that routes through that Python. It edits your profile and, if
     needed, sets your execution policy to RemoteSigned for your user only
     (no admin). Want me to do that?

Person: not now

You: No problem, skipping it. To use `plexavo` in your own terminals later,
     the README's Windows Option 1 has those lines.
     Which AWS profile should I scan? I see: "default".
```

## Explicitly out of scope

The MCP server and multi-hop cross-account trust graphs are not part of
this skill. If asked about either, say they're not supported yet rather
than attempting to improvise something that looks like support for them.
