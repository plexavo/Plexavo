# Security Policy

Plexavo reads AWS account state to find misconfigurations. A vulnerability
in *this tool* — something that could leak scanned data, escalate its own
permissions, or execute unintended code — is a serious issue and deserves
a private reporting path, not a public GitHub issue.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Use GitHub's private vulnerability reporting instead:

1. Go to the **Security** tab of this repository
2. Click **Report a vulnerability**
3. Describe the issue, ideally with steps to reproduce

<!-- TODO(maintainer): if you'd rather offer a direct email as a fallback
     for reporters who don't have a GitHub account, add it here, e.g.:
     security@plexavo.dev — but keep this monitored; a security contact
     nobody checks is worse than not listing one. -->

You should get an acknowledgment within a few days. This is a young,
solo-maintained project — "a few days," not "a few hours," is the honest
expectation to set, not an optimistic one.

## What's in scope

- The scanning engine itself (`plexavo/checks/`, `plexavo/auth.py`,
  `plexavo/principals.py`) — anything that could cause it to
  mis-report a security state, access more than it should, or leak
  scanned findings anywhere they shouldn't go.
- The report generators (`plexavo/report/`) — especially anything that
  could turn AI-narrated or raw finding content into executable code in
  the HTML report (XSS via a crafted resource name or narration, for
  example).
- The packaging/install path — anything that could execute unintended
  code on install (`pyproject.toml`, `setup` hooks if any get added later).

## What's out of scope

- Misconfigurations *in your own AWS account* that Plexavo correctly
  detects and reports — that's the tool working as intended, not a
  vulnerability in the tool.
- Vulnerabilities in AWS services themselves — report those to AWS.
- The AI narration layer producing an inaccurate or incomplete
  explanation — that's a quality bug (open a normal issue), not a
  security vulnerability, unless the inaccuracy is itself
  security-relevant (e.g., a fix suggestion that would make things worse).

## Disclosure

Coordinated disclosure, please — report privately first, give a reasonable
window to land a fix, and we'll credit you in the release notes (unless
you'd rather stay anonymous) once it's out.
