# Contributing to Plexavo

Thanks for looking at this. Plexavo's whole value proposition is that the
checks are real, tested, and honest about what they do and don't catch —
that only holds up if contributions keep that bar. This doc exists so
adding a check doesn't require reverse-engineering the pattern from scratch.

## Before you write code

Open an issue first for anything beyond a trivial fix — a new check, a
change to scoring, a change to the report. Saves you from building
something that doesn't fit, and saves the maintainer from reviewing
something built without pre-agreement on the approach.

## Adding a new check

Every check lives in `plexavo/checks/<category>.py` (`iam.py`, `network.py`,
`storage.py`, `encryption.py`, `logging.py`, `usage.py`, `iam_hygiene.py`)
and follows the same shape. Here's the pattern, annotated:

```python
from plexavo.findings import Finding, Severity

def check_99(session, some_context) -> list[Finding]:
    """One line: what this check looks for, and why it matters.

    A second paragraph, if needed, on any real-world nuance — false
    positives you deliberately excluded, edge cases the check knows about,
    anything a reviewer would otherwise have to reverse-engineer from the
    code itself.
    """
    findings = []
    client = session.client("some-aws-service")

    # ... call the AWS API, evaluate the condition ...
    if condition_is_bad:
        findings.append(Finding(
            check_id="CAT-99",
            title="Short, specific title",
            severity=Severity.HIGH,  # CRITICAL / HIGH / MEDIUM / LOW — see below
            resource_arn=resource_arn,
            raw_detail="One sentence, specific enough to act on without the AI narration layer.",
            account_context=account_context,
        ))
    return findings


def run_all(session, *args) -> list[Finding]:
    """Every category module exposes run_all() — this is what cli.py calls."""
    findings = []
    findings += check_99(session, *args)
    return findings
```

**Severity is a judgment call, not a formula** — base it on realistic
blast radius (what can an attacker actually reach from here) rather than
theoretical worst case. If you're not sure, say so in the PR description
and it'll get discussed there rather than guessed at.

**`raw_detail` matters on its own, not just as AI input.** Most OSS users
will never set `ANTHROPIC_API_KEY` — for them, `raw_detail` *is* the entire
finding description. Write it as if the AI narration layer doesn't exist.

## Testing a new check

Every check needs an offline test in `tests/test_<category>_offline.py` —
fake AWS API responses (see the existing tests for the pattern: a small
factory function building the relevant boto3 response shape), not live
AWS calls. At minimum:

- A **fires** test: the condition you're checking for is present, the
  check produces a `Finding`.
- A **false-positive guard**: the condition looks similar but isn't
  actually the problem, the check produces nothing. These are usually
  more valuable than the fires test — a check that fires on things it
  shouldn't erodes trust in every other check's output too.

Run the full suite before opening a PR:

```bash
for f in tests/test_*.py; do python "$f" || echo "FAILED: $f"; done
```

(A proper `pytest`-based conversion of this test suite, plus a CI
workflow that runs it automatically on every PR, is an open item —
see the issues list. Contributions toward that are especially welcome.)

## What won't get merged

- Anything that requires write access to the scanned account by default.
  Auto-fix is a real, planned feature, but it's staged behind explicit
  user approval and a dry-run/diff-preview mode — it doesn't land as a
  drive-by addition to an unrelated PR.
- Anything that calls a third-party API as part of the *default* scan
  path. The AI narration layer is opt-in with the user's own key for a
  reason (see `plexavo/report/ai_narration.py`) — that principle applies
  to any future integration too.
- New hard dependencies for something only a minority of users need.
  Follow the pattern in `pyproject.toml`'s `[project.optional-dependencies]`
  instead.

## Reporting a vulnerability

Not here — see `SECURITY.md`.
