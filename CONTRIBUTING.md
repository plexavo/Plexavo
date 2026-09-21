# Contributing to Plexavo

You don't need to understand the whole codebase to help.

Plexavo's value is that its checks are real, tested, and honest about
what they do and don't catch. This guide keeps the entry point simple and
the quality bar where it is.

## Ways to help

Only the last two involve writing Python.

- **Break Plexavo:** run a scan and report a miss, a false positive, or
  confusing output. [Open a report](../../issues/new?template=break-plexavo.yml).
  No code needed.
- **Test it on a real setup:** run Plexavo against a test AWS account and
  tell us what was wrong or unclear.
- **Improve docs or report wording:** fix anything that confused you.
- **Add or strengthen a test:** see [Testing a new check](#testing-a-new-check).
- **Add a security check:** see [Adding a new check](#adding-a-new-check).

> [!TIP]
> **New here?** Pick an issue labeled
> [`good first issue`](../../issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
> and comment that you'd like to take it. Questions are welcome there.

## Set up

```bash
git clone https://github.com/plexavo/Plexavo.git
cd Plexavo
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

> [!NOTE]
> On Windows, use `python -m` for everything, as in the README. Smart App
> Control can block the `.exe` launchers a venv generates.

Plexavo supports Python 3.9 and up, and CI runs 3.9 through 3.14. If you
use `X | Y` in a type annotation, add `from __future__ import annotations`
at the top of the file or it breaks on 3.9.

## Run the tests

No AWS account or credentials needed. Every test uses fake API responses.

```bash
python tests/test_storage_offline.py    # one file
for f in tests/test_*.py; do python "$f" || echo "FAILED: $f"; done    # all of them, like CI
```

On Windows PowerShell, the full run is:

```powershell
Get-ChildItem tests\test_*.py | ForEach-Object { python $_.FullName; if ($LASTEXITCODE) { "FAILED: $_" } }
```

The tests are plain scripts, not `pytest` functions. Converting them to
`pytest` is an open item, and a welcome contribution.

## Adding a new check

For a new check, a scoring change, or a report change, open an issue first
(or comment on an existing one). It saves you from building something that
doesn't fit. Small fixes and typos can go straight to a PR.

**The easiest way in:** copy a small existing check, such as
`check_22_access_logging_disabled` in `plexavo/checks/storage.py`, along
with its tests in `tests/test_storage_offline.py`.

Every check lives in `plexavo/checks/<category>.py` (`iam.py`,
`network.py`, `storage.py`, `encryption.py`, `logging.py`, `usage.py`,
`iam_hygiene.py`) and follows this shape:

```python
from plexavo.findings import Finding, Severity


def check_99_example(s3, bucket_names: list) -> list[Finding]:
    """CAT-99: one line on what this looks for and why it matters.

    Add a paragraph on real-world nuance if there is any: false positives
    you deliberately excluded, edge cases, anything a reviewer would
    otherwise have to work out from the code.
    """
    findings = []
    for name in bucket_names:
        config = s3.get_bucket_something(Bucket=name)  # call the AWS API
        if condition_is_bad(config):
            findings.append(Finding(
                check_id="CAT-99",
                title="Short, specific title",
                severity=Severity.MEDIUM,  # CRITICAL / HIGH / MEDIUM / LOW
                resource_arn=f"arn:aws:s3:::{name}",
                raw_detail="One or two sentences, specific enough to act on without AI narration.",
                evidence="The concrete fact behind it, e.g. logging_enabled=False",
            ))
    return findings
```

Then add one line to the category's `run_all()`, which `cli.py` already
calls:

```python
findings += check_99_example(s3, bucket_names)
```

`evidence` is shown to the reader directly, so put the real account-state
fact there. If the check can't be fully certain (a `Condition` block, for
example), lower `confidence` instead of hiding the doubt in prose. Search
for `confidence=` in `plexavo/checks/iam.py` for examples.

> [!TIP]
> **Severity is a judgment call, not a formula.** Base it on realistic
> blast radius (what an attacker can actually reach from here), not the
> theoretical worst case. Not sure? Say so in the PR and it gets discussed
> there.

> [!NOTE]
> **`raw_detail` matters on its own.** Most users never set
> `ANTHROPIC_API_KEY`, so for them `raw_detail` is the entire finding
> description. Write it as if AI narration doesn't exist.

## Testing a new check

Add an offline test in `tests/test_<category>_offline.py`: a small fake
client that returns the boto3 response shape, plus `assert_true` checks.
The existing test files show the pattern. At minimum:

- **A fires test:** the condition is present, the check produces a
  `Finding`.
- **A false-positive guard:** the condition looks similar but isn't the
  problem, and the check produces nothing. These are usually the more
  valuable test, because a check that fires on things it shouldn't erodes
  trust in every other check's output too.

## Opening a PR

Before you open it:

- The full test suite passes.
- New checks have both a fires test and a false-positive guard.
- The severity and `raw_detail` make sense without AI narration.
- If a matching `docs/*-TEST-MATRIX.md` exists, add an entry and say
  plainly whether the check was verified only with fake responses or
  against a real account.

## What won't get merged

> [!IMPORTANT]
> These keep Plexavo local-first and safe to run.

- **Write access to the scanned account by default.** Auto-fix is a
  planned feature, but only behind explicit user approval and a
  dry-run/diff preview. It won't arrive inside an unrelated PR.
- **Third-party API calls in the default scan path.** AI narration is
  opt-in with the user's own key (see `plexavo/report/ai_narration.py`),
  and that principle applies to any future integration too.
- **New hard dependencies for something few users need.** Use
  `[project.optional-dependencies]` in `pyproject.toml` instead.

## Reporting a vulnerability

Not here. See [`SECURITY.md`](SECURITY.md).
