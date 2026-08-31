<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/plexavo-logo-dark.png">
    <img src="assets/plexavo-logo-light.png" alt="Plexavo" height="90">
  </picture>
</div>

# Plexavo

An open-source AWS misconfiguration scanner that reads your account with
your own local AWS credentials — nothing is ever handed to anyone else.
Run it yourself, the same way you'd run `aws s3 ls`, and get a 0-100
security score plus a plain-English report explaining exactly what's
wrong, what an attacker would actually do with it, and the exact command
to fix it.

Deterministic detection (pure Python/boto3, never AI) finds the
misconfigurations. Claude only rewrites already-computed technical
findings into a narrative a non-security founder can act on — it never
decides what counts as a finding, and it's entirely optional (see
[Cost](#cost) below).

## What it checks

**31 checks across 6 categories**, all validated against real, live AWS
accounts (not just offline logic) unless a specific, stated limitation
made that impossible — see the individual `docs/*-TEST-MATRIX.md` files
for exactly which checks are fully verified and which have a documented,
structural reason they can't be (e.g. some checks can only prove their
"clean" case without disabling a real security control to test the "bad"
case).

| Category | Checks | What it catches |
|---|---|---|
| IAM (`iam.py`, `iam_hygiene.py`) | 14 | Privilege escalation paths, wildcard admin, cross-account trust, root usage, dormant credentials |
| Network (`network.py`) | 4 | Security groups and RDS instances exposed to the internet |
| Storage (`storage.py`) | 3 | Public S3 buckets, via ACLs, bucket policies, or missing Block Public Access |
| Encryption (`encryption.py`) | 3 | Unencrypted EBS volumes, RDS instances, S3 default encryption |
| Logging (`logging.py`) | 4 | CloudTrail coverage/encryption, GuardDuty status |
| Usage analysis (`usage.py`) | 2 (+1 skipped, duplicate of an IAM check) | Granted permissions never actually used, roles nobody has assumed in 90+ days — the hardest category, built last, uses real CloudTrail history |

Plus `scoring.py` (the 0-100 score) and `plexavo/report/ai_narration.py`
(the opt-in AI layer).

## Example output

Illustrative example (a public S3 bucket, an unencrypted volume, a role that's
never been assumed) — this is what a scan actually surfaces, including a
finding's free template remediation (shown by default, no `--explain`
needed; `--explain` would replace this panel with a full AI narrative
instead):

```
Your AWS Security Score: 74/100 (Good)

                                              Findings (3)
┏━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Check   ┃ Severity ┃ Resource                           ┃ Detail                                     ┃
┡━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ STOR-19 │ Critical │ arn:aws:s3:::taskflow-uploads-prod │ Bucket 'taskflow-uploads-prod' allows      │
│         │          │                                    │ public read via bucket policy.             │
│ ENC-29  │ Medium   │ vol-015506d04acb46ca9              │ EBS volume 'vol-015506d04acb46ca9' is not  │
│         │          │                                    │ encrypted at rest.                         │
│ USE-27  │ High     │ AWSSecurityScannerReadOnlyRole     │ Role 'AWSSecurityScannerReadOnlyRole' has  │
│         │          │                                    │ never been assumed since creation.         │
└─────────┴──────────┴────────────────────────────────────┴────────────────────────────────────────────┘

╭────────────────────────────────────────── source: template ──────────────────────────────────────────╮
│ STOR-19 — arn:aws:s3:::taskflow-uploads-prod                                                         │
│                                                                                                      │
│ IMPACT: Bucket 'taskflow-uploads-prod' doesn't have full S3 Block Public Access protection enabled.  │
│ Without this protection, a single mistake — an overly broad bucket policy, a public ACL grant,       │
│ someone copy-pasting a policy from a tutorial — immediately exposes every object to anyone on the    │
│ internet via a plain s3:GetObject call, with nothing left to catch the mistake.                      │
│                                                                                                      │
│ CONFIDENCE: Confirmed                                                                                │
│                                                                                                      │
│ NEXT STEP: Turn on Block Public Access now: aws s3api put-public-access-block --bucket               │
│ taskflow-uploads-prod --public-access-block-configuration                                            │
│ "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"       │
│                                                                                                      │
│ FULL FIX DETAIL: Enable all four Block Public Access settings unless there's a specific, documented  │
│ reason not to:                                                                                       │
│ aws s3api put-public-access-block --bucket taskflow-uploads-prod --public-access-block-configuration │
│ "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"        │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

Severity, confidence, and evidence are always separate signals, never merged
into one label — a low-confidence Critical and a high-confidence Medium don't
read the same. This particular finding has no Evidence line because it's a
directly-observed fact with nothing uncertain about it — Evidence only appears
when a check has a concrete account-state fact behind it (e.g. an IAM policy
scoped by a Condition block, or a CloudTrail lookup that hit its page cap on
`USE-26`), and Confidence only drops from "Confirmed" in that same situation.
`--report-html`/`--report-pdf` render this same data as a full report; see
[Cost](#cost) for what `--explain` needs and what it costs.

## Quick start

The install path depends on your OS — **uv on macOS & Linux**, **pip on
Windows**. Either way it's a one-command install with no venv to create,
activate, or reactivate in every new terminal.

### macOS & Linux — uv

[uv](https://docs.astral.sh/uv/) installs Plexavo into its own isolated
environment automatically.

**1. Install uv** (if you don't already have it):

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

(Full options: [uv installation docs](https://docs.astral.sh/uv/getting-started/installation/).)

**2. Install Plexavo:**

```bash
uv tool install plexavo
```

That's it — `plexavo` is now on your PATH in every terminal, until you
uninstall it. No activate step, ever.

**Have an Anthropic API key and want AI-narrated explanations** (see
[Cost](#cost) — it's optional and costs a few cents per scan, not
free)? Install with the `[ai]` extra instead — same package, just with
the `anthropic` library included:

```bash
uv tool install "plexavo[ai]"
```

No key yet, or not sure? Skip it for now — the plain install is
genuinely complete on its own. Add it later with:

```bash
uv tool install --reinstall "plexavo[ai]"
```

Just want to try it once without installing anything?

```bash
uvx plexavo scan --profile my-aws-profile
```

Updating or removing later:

```bash
uv tool upgrade plexavo
uv tool uninstall plexavo
```

### Windows — pip

Install with `pip` and run the tool as `py -m plexavo`:

```powershell
py -m pip install --user plexavo
py -m plexavo
```

`py -m plexavo` with no arguments opens the interactive menu, exactly
like the `plexavo` command does on macOS/Linux — flags are only for
scripting/CI.

> **Why not uv/pipx on Windows?** Both work by putting a small generated
> `plexavo.exe` launcher on your PATH. That launcher is unsigned, and
> Windows Smart App Control blocks unsigned executables it doesn't
> recognise — so `plexavo` can fail to start with a "can't confirm who
> published" message. `py -m plexavo` calls Python directly and never
> touches that launcher, so it always works. (If your machine doesn't
> enforce Smart App Control, `uv tool install plexavo` works here too.)

**AI-narrated explanations** (see [Cost](#cost)):

```powershell
py -m pip install --user "plexavo[ai]"
```

Updating or removing later:

```powershell
py -m pip install --user --upgrade plexavo
py -m pip uninstall plexavo
```

### Optional: type `plexavo` instead of `py -m plexavo`

Add a shortcut to your PowerShell profile once:

```powershell
Add-Content $PROFILE 'function plexavo { py -m plexavo @args }'
```

Open a new terminal and `plexavo` then works just like it does on
macOS/Linux.

### Run a scan

```bash
plexavo scan --profile my-aws-profile --report-html report.html
```

(On Windows without the shortcut above: `py -m plexavo scan --profile
my-aws-profile --report-html report.html`.)

No `--profile`? It uses your default profile / environment variables,
same resolution order as the AWS CLI. No AI, no API key, no cost — and
findings still come with free Next Step / Full Fix Detail guidance
wherever a template exists (10 common check types); this alone is a
complete, genuinely useful scan.

Want a full AI-written explanation for *every* finding instead (needs
the `[ai]` install above)?

```bash
export ANTHROPIC_API_KEY="sk-ant-..."   # your own key, your own account
plexavo scan --profile my-aws-profile --explain --report-html report.html --report-pdf report.pdf
```

- Drop `--explain` and findings still get free template remediation where
  available (no API key needed) and raw technical detail otherwise.
  `--explain` replaces that with a live AI narrative for every finding,
  including the templated ones.
- Drop `--report-html`/`--report-pdf` to just see the console table.
- `--explain-limit N` (default 25) caps how many findings get a live AI
  call when `--explain` is passed, as a safety rail against unexpectedly
  large real scans — it doesn't limit the free template remediation.
- No `ANTHROPIC_API_KEY` set, or a call fails for any reason (invalid key,
  rate limit, network issue)? The scan and report are completely
  unaffected — that finding falls back to template/raw detail instead of
  an AI narrative, not an error. See [Cost](#cost).

### Alternative: pipx

Already use [pipx](https://pipx.pypa.io/) on macOS/Linux? It works exactly
the same way as uv — its own isolated environment, one global command, no
venv:

```bash
pipx install plexavo
pipx install "plexavo[ai]"   # with AI-narrated explanations
```

On Windows, pipx has the same Smart App Control caveat as uv (see the
Windows section above) — if the `plexavo` command is blocked, run
`py -m plexavo` instead, or use the `pip` install.

### Alternative: pip + venv

Want full isolation and prefer to manage the environment yourself? Modern
Python (PEP 668) blocks a plain `pip install` outside a venv on many
Linux and Homebrew setups, so create one first:

```bash
python -m venv plexavo-env
plexavo-env\Scripts\activate      # Windows
source plexavo-env/bin/activate   # Mac/Linux

pip install plexavo
pip install "plexavo[ai]"   # with AI-narrated explanations
```

You'll need to reactivate this venv (`plexavo-env\Scripts\activate` /
`source plexavo-env/bin/activate`) every time you open a new terminal —
`deactivate` exits it without uninstalling anything. On Windows, run
`python -m plexavo` if the `plexavo` command is blocked by Smart App
Control.

### From source (for contributing, or trying an unreleased change)

```bash
git clone https://github.com/plexavo/plexavo.git
cd plexavo
uv pip install -e .   # or: pip install -e . (inside a venv)
```

## Project structure

```
plexavo/
├── auth.py                    # local AWS credential resolution
├── principals.py               # enumerates IAM users/roles + their policies
├── findings.py                  # Finding data model, Severity enum
├── scoring.py                    # 0-100 score from a list of Findings
├── cli.py                         # `plexavo scan ...` entry point
├── __main__.py                      # lets `python -m plexavo` run the CLI
├── checks/
│   ├── iam.py                       # IAM-01 to IAM-06 (privilege escalation)
│   ├── iam_hygiene.py                # IAM-07 to IAM-14 (hygiene, cross-account trust)
│   ├── network.py                     # NET-01 to NET-04
│   ├── storage.py                      # STOR-19 to STOR-21
│   ├── encryption.py                    # ENC-29 to ENC-31
│   ├── logging.py                        # LOG-22 to LOG-25
│   └── usage.py                           # USE-26, USE-27
└── report/
    ├── html_report.py               # assembles findings into HTML via Jinja2
    ├── pdf.py                        # same data, rendered to PDF via fpdf2
    ├── ai_narration.py                # opt-in Claude narration + the 10 free templates
    ├── fonts/                          # bundled DejaVu Sans (PDF) + Geist (HTML) —
    │                                     both self-hosted, zero external requests
    └── templates/report.html.j2         # the HTML report template

examples/
└── quickstart-sandbox.tf       # one cheap, deliberately-public S3 bucket —
                                  try the scanner without pointing it at
                                  real infrastructure on day one

tests/
└── test_*.py                   # one per module, no AWS calls, run anytime:
                                  python tests/test_iam_offline.py, etc.

docs/
├── *-TEST-MATRIX.md            # one per category — the actual grading
│                                  record: what's verified, how, and any
│                                  stated limitation. Start here if you
│                                  want to know how much to trust a
│                                  given check.
├── COMPARISON.md               # honest, hands-on comparison against
│                                  Prowler, ScoutSuite, and PMapper
├── TECHNICAL-EXPLAINER.md      # implementation decisions and why
└── HOW-IT-WORKS.md
```

## Cost

Detection is free (pure Python/boto3), always, regardless of anything
else in this section. Every scan also gets free Next Step / Full Fix
Detail remediation wherever one of 10 hand-written templates matches the
finding type — no flag, no API key, zero cost, on by default.

Live AI only runs with `--explain`, and when it does it's used for
*every* finding, including the 10 templated ones (a deliberate choice —
"AI narration on" always means fully AI-written content, not a mix of
template and AI), typically $0.01-0.02 per finding depending on answer
length. A full scan with `--explain` on a real account is usually well
under a dollar. This is **your own** `ANTHROPIC_API_KEY`, in **your own**
Anthropic account — this project never sees your key, never embeds one of
its own, and never calls the API on your behalf without you having set
one. Not "free AI" — bring your own key, and a scan with it enabled costs
a few cents.

## Running the tests

```bash
pip install -e ".[dev]"
for f in tests/test_*.py; do python "$f"; done
```

Each is self-contained — fake AWS API responses, no real credentials or
network calls needed. See `docs/TEST-MATRIX.md` for how these map to
live-AWS verification.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) — in particular, the pattern for
adding a new check.

## Security

Found a vulnerability in the tool itself (not a misconfiguration in your
own AWS account — that's the tool working correctly)? See
[`SECURITY.md`](SECURITY.md) for a private reporting path.

## License

AGPL-3.0 — see [`LICENSE`](LICENSE). You can use, run, and modify this
freely. If you run a modified version as a hosted service, you're
required to publish those modifications too. This is deliberate: it's
the specific protection against a well-resourced company taking this
code and standing up a competing hosted product without ever
contributing back.
