# Running Plexavo on a schedule

Plexavo is a normal command-line tool, so anything that can run a command
on a timer can run Plexavo. Nothing new has to be built or installed for
this. This page shows two working setups, a cron job and a GitHub Actions
workflow, plus how to get notified when something regresses without
opening a report by hand.

## What actually gets scanned

Plexavo scans a live AWS account through the AWS APIs, using whatever
credentials you give it. It does not read Terraform, CloudFormation, or
any other infrastructure code. It sees the real current state of the
account no matter how that state got there, which also means it catches
things changed by hand in the console that never made it back into your
templates.

So a scheduled scan needs exactly one thing: AWS credentials with
read-only access. It does not need your application code or your
infrastructure repo.

## Option 1: cron

On any machine that stays on (a small VM, a home server, a Raspberry Pi),
add a crontab entry:

```cron
# Scan the "prod" profile every day at 08:00, writing a dated HTML report
0 8 * * * cd /opt/plexavo && /usr/local/bin/plexavo scan --profile prod --report-html "reports/plexavo-$(date +\%F).html" --fail-on high
```

Notes:

- `cd` into a directory Plexavo can write to. cron runs with a bare
  environment and a different working directory than your shell.
- Use the full path to the `plexavo` binary (`which plexavo` to find it).
  cron does not load your usual `PATH`.
- The `\%` is not a typo. cron treats a bare `%` as a newline, so it has
  to be escaped.
- Instead of `--profile prod` you can export `AWS_ACCESS_KEY_ID`,
  `AWS_SECRET_ACCESS_KEY`, and `AWS_DEFAULT_REGION` in the cron
  environment.
- `--fail-on high` is explained under "Getting notified" below.

If the scan exits non-zero, cron emails the crontab owner, provided the
host has mail delivery configured. That is the cron equivalent of the
GitHub notification described below.

## Option 2: GitHub Actions

If you use GitHub, a scheduled workflow gives you an always-on scheduler,
a throwaway runner, and a notification path, all for free, without
running a server.

Put this in an existing private repo, or create a small private repo just
for it. The workflow never touches your other code.

`.github/workflows/plexavo-scan.yml`:

```yaml
name: plexavo scan

on:
  schedule:
    - cron: "0 8 * * *"   # every day at 08:00 UTC
  workflow_dispatch: {}    # also run it by hand from the Actions tab

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install Plexavo
        run: pip install plexavo

      - name: Run the scan
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          AWS_DEFAULT_REGION: us-east-1
        run: plexavo scan --report-html report.html --fail-on high

      - name: Upload the report
        if: always()   # keep the report even when the scan exits non-zero
        uses: actions/upload-artifact@v4
        with:
          name: plexavo-report
          path: report.html
```

Setup:

1. Add the file above to the repo's default branch.
2. Create the AWS credentials (see "Credentials" below), then add them
   under Settings, Secrets and variables, Actions as `AWS_ACCESS_KEY_ID`
   and `AWS_SECRET_ACCESS_KEY`.
3. Push. The schedule starts on its own. Use "Run workflow" on the
   Actions tab to test it right away.

Two things to know about GitHub's scheduler:

- Scheduled workflows only run from the default branch.
- GitHub disables the schedule after roughly 60 days with no activity in
  the repo. A commit or a manual run resets that. For a repo that exists
  only for this, running it by hand occasionally is enough.

Want the full AI-written narration in the report? Install `"plexavo[ai]"`
instead of `plexavo` and add `ANTHROPIC_API_KEY` as another secret. It is
not required. Without it every finding still gets free template
remediation.

### Where the report goes

Each run stores `report.html` as a build artifact on the run's page in
the Actions tab. Download it from there. Artifacts are private to people
with repo access and are kept 90 days by default (change that with
`retention-days` on the upload step). The report is never committed back
into the repo and never leaves GitHub.

For the cron setup, the report is just a file on that machine's disk,
wherever you pointed `--report-html`.

## Getting notified without checking manually

`plexavo scan` normally exits 0 whether or not it finds anything. Pass
`--fail-on` to change that:

```
plexavo scan --report-html report.html --fail-on high
```

With `--fail-on high`, Plexavo exits with status 2 if any finding is High
or Critical. The report is still written first. `--fail-on critical`,
`--fail-on medium`, and `--fail-on low` move the bar.

That non-zero exit is the whole notification mechanism:

- GitHub Actions marks the run failed, shows a red X on the repo, and
  emails you. It is the same notification you already get for a broken
  build, reused for "your AWS account regressed."
- cron emails the crontab owner on any non-zero exit.

No Slack app, no webhook, no extra service. Exit status 1 stays separate:
it means the scan itself could not run (bad credentials, no region, and
so on), which is a different problem from the scan running fine and
finding something.

### The limitation to know about

`--fail-on` trips on any finding at or above the threshold, not only on
new ones. It has no memory of previous runs. If your account already has
High findings, every run fails until you fix them or raise the threshold.
It is a tripwire for "is anything at this severity present," not "did
something change since yesterday."

Alerting only on newly introduced findings (a diff between runs) is
planned as a separate feature. Until then, the practical pattern is to
fix or accept everything at your chosen threshold once, so that a later
failure genuinely means something new.

## Credentials

This is the part not to rush, because getting it wrong undoes the reason
to trust the tool in the first place.

Do not reuse a personal access key or an admin credential. Create a
dedicated identity that can only read.

### A dedicated read-only IAM user

1. Create a new IAM user (for example `plexavo-scanner`) with
   programmatic access only, no console password.
2. Attach the AWS managed policy `SecurityAudit`. It is built for exactly
   this: read-only visibility across the services a security review looks
   at, and it already covers everything Plexavo calls.
3. Create an access key for that user and put it in GitHub Secrets, or on
   the cron host.

`SecurityAudit` is broader than Plexavo strictly needs, but it is AWS
maintained, so it does not silently fall behind when Plexavo adds a
check. If you want to scope it down further: Plexavo only makes
`Describe`, `List`, and `Get` style calls, across IAM, EC2, RDS, S3,
CloudTrail, GuardDuty, Lambda, and STS. Verify the exact set against the
current code rather than copying a hand-written policy from anywhere,
this page included, because the set grows as checks are added:

```bash
grep -rnE 'client\(|get_paginator\(|\.(get|list|describe|lookup)_' plexavo/checks plexavo/principals.py plexavo/auth.py
```

Plexavo never needs, and should never be given, any action that writes,
creates, modifies, or deletes.

### Better: no stored key at all (GitHub OIDC)

On GitHub you can skip the long-lived access key entirely. Configure an
IAM role that trusts GitHub's OIDC provider and let the workflow assume
it at run time with `aws-actions/configure-aws-credentials` (this needs
`permissions: id-token: write` on the job). There is nothing to store or
rotate. It takes more setup; AWS and GitHub both document it. The role
still gets `SecurityAudit` and nothing more.

## After it is running

Once a scheduled scan exists, it is a concrete thing to point to when
someone asks whether they can get pinged instead of checking manually.
The answer is yes, and this is how.
