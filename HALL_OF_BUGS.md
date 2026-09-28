# Hall of Bugs

"Break Plexavo" is a standing challenge: find a case where the scanner
misses something, gets something wrong, or gives confusing guidance:
false positives, false negatives, weird IAM edge cases, detection
bypasses, unusual AWS service combinations. Report it with the
[Break Plexavo issue template](../../issues/new?template=break-plexavo.yml).
Every confirmed, genuinely new finding gets fixed and shipped in a real
release, and you get a permanent entry here, credited by name.

No bounty, no money. Public credit only.

## What doesn't count

Reporting a gap that's already publicly documented as a known limitation
isn't a new find. Currently documented, non-qualifying limitations:

- Multi-hop privilege escalation chains (A can assume B, B can assume C,
  C is admin). Only one-hop detection exists today.
- Cross-account trust resolution. Plexavo flags that a role trusts an
  external account, but doesn't trace into that account's own
  identities.
- IAM-12 (root account usage) intentionally has no blanket remediation
  template, since the correct response depends on the specific action
  taken and a one-size-fits-all answer would sometimes be wrong.

This list is updated any time a new limitation is intentionally
documented, so the boundary here stays honest.

## Entries

🏆 Bug #1
S3 bucket-level server access logging was never checked at all. A
bucket with logging genuinely disabled produced no finding, not because
of a bug in existing detection logic, but because no check for it
existed anywhere in the codebase. Fixed by adding STOR-22.
Found by: @ThePettyReviewer
Category: False Negative
Fixed in: v0.2.7

🏆 Bug #2
STOR-22's finding text claimed that with server access logging off,
"investigation after the fact isn't possible." That overclaims: S3
object-level access is often captured by CloudTrail S3 data events
instead, and Plexavo doesn't check for that — so it can't actually
know a bucket is unauditable. For tightly scoped, otherwise-audited
buckets (e.g. petabyte-scale private-subnet workloads) the old wording
read as a false alarm. Fixed by rewriting the STOR-22 detail to
describe what server access logging provides and to note the finding
may be lower priority where access is already scoped and audited
another way. Severity stays Medium — unchanged — since the default
still needs to warn the majority of users for whom this is a real gap.
Found by: @dghah
Category: Inaccurate Finding Language
Fixed in: v0.2.8 (pending release)

🏆 Bug #3
One S3 bucket the scanning principal couldn't read (AccessDenied, e.g. an
explicit Deny in that bucket's own policy) crashed the entire scan —
STOR-19 through STOR-22 re-raised instead of handling it, so an account
with 49 readable buckets and 1 denied one got zero findings, not 49.
Fixed by skipping the unreadable bucket per check and reporting it as
unevaluated instead of raising.
Found by: @fusiontechstrategies
Category: Edge Case
Fixed in: v0.4.6 (pending release)

🏆 Bug #4
IAM-05 and IAM-06 both missed an sts:AssumeRole grant scoped to
"role/*" (assume any role in the account) — the resource matcher only
recognized a literal "*", never a prefix-wildcard ARN, so this
one-hop-to-full-admin case produced no finding at all. Fixed with real
ARN wildcard matching, the same fix already shipped for the Action
field in v0.4.5, now applied to Resource too.
Found by: @fusiontechstrategies
Category: False Negative
Fixed in: v0.4.6 (pending release)

🏆 Bug #5
USE-26 flagged actively-used data-plane actions (s3:GetObject,
dynamodb:GetItem, lambda:InvokeFunction, and similar) as unused, at
Confirmed confidence, recommending removal — CloudTrail's LookupEvents
API only ever returns management events, so these can never show up as
"used" regardless of real activity. Fixed by excluding known data-plane
actions from consideration entirely, rather than confidently calling
them unused.
Found by: @fusiontechstrategies
Category: False Positive
Fixed in: v0.4.6 (pending release)

🏆 Bug #6
USE-27 flagged nearly every role as "never assumed," even roles used
minutes earlier — list_roles' own RoleLastUsed field proved unreliable,
while get_role for the same role returns it correctly. Fixed by
fetching each role's data via get_role, the same fix already used
elsewhere in this codebase for the same AWS quirk.
Found by: @fusiontechstrategies
Category: False Positive
Fixed in: v0.4.6 (pending release)

🏆 Bug #7
STOR-20 flagged a Principal:* bucket policy as fully public even when a
Condition block (e.g. aws:PrincipalOrgID) genuinely scoped it down — a
normal, safe pattern with CloudFront and org-wide internal buckets.
Fixed by applying the same Condition-aware downgrade every IAM check
already used, so a conditioned grant now reads High/"Likely — see note"
instead of Critical/Confirmed.
Found by: @fusiontechstrategies
Category: False Positive
Fixed in: v0.4.6 (pending release)
