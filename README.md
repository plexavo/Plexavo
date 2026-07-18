<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/plexavo-logo-dark.png">
  <img src="assets/plexavo-logo-light.png" alt="Plexavo" height="60">
</picture>

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

## Quick start

```bash
pip install plexavo
```

(Or from source: `git clone` this repo, then `pip install -e .` from the
repo root.)

Run a scan with your own AWS credentials — no setup beyond what
`aws configure` already gave you:

```bash
plexavo scan --profile my-aws-profile --report-html report.html
```

No `--profile`? It uses your default profile / environment variables,
same resolution order as the AWS CLI. No AI, no API key, no cost — this
alone is a complete, genuinely useful scan.

Want plain-English explanations for each finding too:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."   # your own key, your own account
plexavo scan --profile my-aws-profile --explain --report-html report.html --report-pdf report.pdf
```

- Drop `--explain` for a fast, free scan with raw technical findings only.
- Drop `--report-html`/`--report-pdf` to just see the console table.
- `--explain-limit N` (default 25) caps how many findings get AI narration
  in one run, as a safety rail against unexpectedly large real scans.
- No `ANTHROPIC_API_KEY` set, or a call fails for any reason (invalid key,
  rate limit, network issue)? The scan and report are completely
  unaffected — you get raw finding detail instead of narration for that
  finding, not an error. See [Cost](#cost).

## Project structure

```
plexavo/
├── auth.py                    # local AWS credential resolution
├── principals.py               # enumerates IAM users/roles + their policies
├── findings.py                  # Finding data model, Severity enum
├── scoring.py                    # 0-100 score from a list of Findings
├── cli.py                         # `plexavo scan ...` entry point
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
else in this section. AI narration only runs with `--explain`, and even
then: 10 of the most common, narratively-generic finding types are
hand-written templates with zero API cost; only genuinely account-specific
findings call Claude, typically $0.01-0.02 per finding depending on answer
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
