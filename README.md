<div align="center">

  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/plexavo-logo-dark.png">
    <img src="assets/plexavo-logo-light.png" alt="Plexavo" height="105">
  </picture>

  <p>
    <a href="https://github.com/plexavo/plexavo">
      <img src="https://img.shields.io/github/stars/plexavo/plexavo?style=for-the-badge&logo=github&label=STARS" alt="GitHub stars">
    </a>
    <a href="https://github.com/plexavo/plexavo/blob/main/LICENSE">
      <img src="https://img.shields.io/github/license/plexavo/plexavo?style=for-the-badge&label=LICENSE" alt="License">
    </a>
    <a href="https://pypi.org/project/plexavo/">
      <img src="https://img.shields.io/pypi/v/plexavo?style=for-the-badge&logo=pypi&logoColor=white&label=PYPI" alt="PyPI version">
    </a>
    <a href="https://github.com/plexavo/plexavo/actions">
      <img src="https://img.shields.io/github/actions/workflow/status/plexavo/plexavo/ci.yml?style=for-the-badge&label=BUILD" alt="Build status">
    </a>
  </p>

  <p><strong>See your cloud. Secure what matters.</strong></p>
  <p>Turn AWS configuration data into clear, actionable security intelligence.</p>

</div>

---

<div align="center">
  <img src="assets/demo.gif" alt="Plexavo interactive scan demo" width="800">
</div>

> [!NOTE]
> **Plexavo is built around a simple idea:** security tooling should tell you what is wrong, why it matters, and what to do next, without requiring a dedicated security team.

Plexavo is an open-source cloud security tool that audits AWS accounts
for real-world misconfigurations, using your own local AWS credentials
the same way `aws s3 ls` does, so nothing about your account ever
leaves your machine.

Each scan produces a **0–100 security score** and a plain-English report:
what's wrong, what an attacker would actually do with it, and the exact
command to fix it.

> [!IMPORTANT]
> **Detection is not AI.** Plexavo's detections are pure Python/boto3;
> Claude only rewrites already-found findings for readability, and
> narration is fully optional. See [Cost](#cost).

> [!TIP]
> 🤖 **New: talk to Plexavo through Claude Code.** No CLI flags, just ask
> "scan my AWS account with Plexavo" in a Claude Code session and get a
> conversational security briefing. See
> [Using it from Claude Code](#using-it-from-claude-code).

## ✦ What it checks

**32 checks across 6 categories**, run against real AWS accounts:

| Category | What Plexavo looks for |
|---|---|
| **IAM** | Privilege escalation paths, wildcard admin, cross-account trust, root usage, dormant credentials |
| **Network** | Security groups and RDS instances exposed to the internet |
| **Storage** | Public S3 buckets via ACLs, bucket policies, or missing Block Public Access; buckets with no access logging |
| **Encryption** | Unencrypted EBS volumes, RDS instances, S3 buckets |
| **Logging** | CloudTrail coverage and encryption, GuardDuty status |
| **Usage** | Permissions granted but never used, roles nobody has assumed in 90+ days |

See `docs/*-TEST-MATRIX.md` for how each check was verified.

> [!TIP]
> **Don't just trust the number.** Plexavo keeps severity, confidence, and evidence as separate signals, so a low-confidence Critical does not read the same as a high-confidence Medium.

## ⚡ Installation

Every path below installs Plexavo into its own isolated environment.

### macOS & Linux

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh   # skip if you have uv
uv tool install plexavo
```

Prefer [pipx](https://pipx.pypa.io/)? `pipx install plexavo` works the
same way.

### Windows

`uv`/`pipx` still work, but the PATH launcher is unsigned and Windows
Smart App Control blocks it. Run Plexavo through Python instead:

**Option 1, uv (recommended)**

```powershell
uv tool install plexavo
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
if (!(Test-Path $PROFILE)) { New-Item -ItemType File -Path $PROFILE -Force }
Add-Content $PROFILE 'function plexavo { & "$env:APPDATA\uv\tools\plexavo\Scripts\python.exe" -m plexavo @args }'
```

Open a new terminal. `plexavo` now works like it does on macOS/Linux,
routed through uv's signed Python instead of the blocked launcher.

**Option 2, plain venv**

```powershell
py -m venv plexavo-venv
.\plexavo-venv\Scripts\Activate.ps1
python -m pip install plexavo
python -m plexavo
```

Use `python -m` for everything here too. The venv's own `pip.exe` and
`plexavo.exe` are unsigned as well, only `python.exe` is signed.

### AI narration (optional)

Want each finding rewritten as a full narrative? Install `"plexavo[ai]"`
instead of `plexavo`, and set `ANTHROPIC_API_KEY`. See [Cost](#cost).

## 🚀 Using Plexavo

Run it with no arguments and it walks you through everything: picking an
AWS profile, choosing HTML or PDF, then scanning and showing your score
with every finding.

```bash
plexavo             # macOS/Linux, and Windows Option 1
python -m plexavo   # Windows Option 2
```

<div align="center">
  <img src="assets/screenshot-cli.png" alt="Plexavo interactive CLI" width="700">
</div>

### Running it on a schedule

Plexavo can also run unattended from cron or a GitHub Actions workflow,
and flag a run when something regresses so you get notified without
opening a report. See [`docs/automation.md`](docs/automation.md).

> [!NOTE]
> **Think of a scan as a snapshot, not a finish line.** Run it repeatedly to catch regressions as your infrastructure changes.

### 🤖 Using it from Claude Code

Using [Claude Code](https://claude.com/claude-code)? Install the
`plexavo-scan` plugin, then just ask: "scan my AWS account for security
issues using Plexavo." It relays exactly what Plexavo found, and never
runs a state-changing AWS command without asking first. Don't have Plexavo
installed yet? It notices, and with your approval at each step installs uv
and Plexavo for you, including the Windows Smart App Control workaround.

```
/plugin marketplace add plexavo/Plexavo
/plugin install plexavo-scan@plexavo
```

Prefer not to add a marketplace? Save
[`plexavo-scan/SKILL.md`](https://raw.githubusercontent.com/plexavo/Plexavo/main/.claude/skills/plexavo-scan/SKILL.md)
to `~/.claude/skills/plexavo-scan/SKILL.md`
(`%USERPROFILE%\.claude\skills\plexavo-scan\SKILL.md` on Windows) instead,
same skill, just without automatic updates.

## 📊 The report

Reports are generated as HTML, PDF, or both. Every finding gets a free,
template-based fix by default, no key, no cost. Full AI-written
narration kicks in automatically once an `ANTHROPIC_API_KEY` is
detected, see [Cost](#cost).

<div align="center">
  <img src="assets/screenshot-report.png" alt="Plexavo HTML report" width="700">
</div>

## 💰 Cost

Detection and the free templates always cost nothing. Live AI only runs
with `--explain`, using **your own** `ANTHROPIC_API_KEY` in **your own**
Anthropic account.

Plexavo never sees your key and never calls the API without it. A full
scan with `--explain` typically costs a few cents.

> [!IMPORTANT]
> **No hidden AI bill.** If you don't provide an Anthropic API key, Plexavo does not make an AI API call.

## 🤝 Contributing

```bash
git clone https://github.com/plexavo/plexavo.git
cd plexavo
uv pip install -e .
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the pattern used to add a
new check.

### 🧨 Break Plexavo

Think you can make Plexavo miss something, or give confusing guidance?

[**Report it →**](../../issues/new?template=break-plexavo.yml)

Every confirmed, genuinely new finding gets fixed and shipped, and you
get a permanent credit in the [Hall of Bugs](HALL_OF_BUGS.md).

**No bounty. Public credit only.**

> [!TIP]
> **The best security tool is one that gets challenged.** If you find a blind spot, break it, report it, and help make the next scan better.

## 🔐 Security

Found a vulnerability in the tool itself, not a misconfiguration in your
own AWS account (that's the tool working correctly)?

See [`SECURITY.md`](SECURITY.md) for a private reporting path.

## 📄 License

AGPL-3.0, see [`LICENSE`](LICENSE).

Use, run, and modify it freely. If you run a modified version as a hosted
service, you're required to publish those modifications too.

---

<div align="center">

**Plexavo · Open-source cloud security, built to be understood.**

<sub>Scan. Understand. Fix. Repeat.</sub>

</div>
