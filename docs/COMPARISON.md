# Tool Comparison — July 15, 2026

A real, same-account comparison of this scanner against Prowler (v5.33.2) and
PMapper (principalmapper v1.1.5) — not a paper comparison. All three ran
against the identical AWS account (111111111111, the "TaskFlow" demo
environment), same infrastructure, same session. Findings below are drawn
directly from the actual outputs produced today, not assumed.

## What was actually tested

The account contained, at scan time: one EC2 instance with SSH open to
0.0.0.0/0, one S3 bucket with no Block Public Access and a public bucket
policy, two unencrypted EBS volumes (one deliberate, one the instance's
auto-created root volume), an IAM user (`taskflow-developer`) with two
active access keys and zero permissions, an IAM role
(`taskflow-ci-deploy-role`) with two explicit non-wildcard permissions and
no escalation path, no CloudTrail trail, no GuardDuty, and root account
usage from creating the CloudFormation access stack (the only way into a
brand-new account with no IAM user yet).

## Our tool's actual results (reference: the saved PDF report, 24 findings)

Score: 0/100 (Critical). 3 ENC, 7 IAM, 2 LOG, 4 NET, 4 STOR, 4 USE. Full
detail already reviewed and two bugs found/fixed as a direct result — see
"Bugs this comparison caught" below.

---

## Prowler

**What it is:** A mature, multi-year, Apache 2.0 open-source project. Multi-
cloud (AWS/Azure/GCP), maps findings to CIS, PCI-DSS, HIPAA, SOC2, ISO27001,
FedRAMP, and more. Widely deployed, actively maintained, large contributor
base.

**Real numbers from today:** 405 checks evaluated (not all 610+ in its
library — many don't apply to services this account doesn't use). 250 FAIL,
152 PASS, 3 MANUAL. Severity spread: 113 low, 97 medium, 37 high, 3
critical.

### Confirmed direct overlaps with our tool (same real fact, both caught it)

| Real issue | Our check | Prowler's check | Notes |
|---|---|---|---|
| Public bucket | STOR-20 | `s3_bucket_public_access` | Exact match, both Critical |
| SSH open | NET-01 | `ec2_instance_port_ssh_exposed_to_internet` | Exact match, both Critical |
| Unencrypted volumes (both) | ENC-29 | `ec2_ebs_volume_encryption` | Exact match on both volume IDs |
| 2 active keys | IAM-11 | `iam_user_two_active_access_key` | Same fact — **we rate High, Prowler rates Medium** |
| Root usage | IAM-12 | `iam_avoid_root_usage` | Exact match, both High |

### Confirmed real gaps in OUR tool, found via Prowler's output

- **`iam_role_cross_service_confused_deputy_prevention`** — Prowler flagged
  `taskflow-ci-deploy-role` for lacking an `sts:ExternalId` or
  `aws:SourceAccount` condition on its EC2-service trust policy, preventing a
  confused-deputy scenario. **We have no equivalent check at all.** This is
  a real, legitimate, currently-missing check.
- **True per-region CloudTrail verification.** Prowler's
  `cloudtrail_multi_region_enabled` ran independently against every
  individual AWS region (`ap-northeast-1`, `ap-northeast-2`,
  `ap-northeast-3`, and more, each its own finding). Our LOG-22/23 are
  account-wide, not per-region-enumerated to this granularity.
- **Sheer service breadth** — Bedrock, SageMaker, FMS, and dozens of other
  services we don't touch at all.

### Confirmed real gaps in PROWLER, found via our own known strengths

- **No general-purpose usage-based unused-permission check.** Prowler's
  closest equivalent, `iam_role_access_not_stale_to_bedrock`, only checks
  staleness for one specific service (Bedrock). Our USE-26 checks *any*
  explicitly granted action against *any* real CloudTrail usage — a
  materially broader mechanism, confirmed by inspecting the actual check ID,
  not assumed.
- **Zero GuardDuty checks fired or appear to have executed in this run.**
  Genuinely surprising given GuardDuty's prominence; our LOG-25 reliably
  catches this.
- **No plain-English narration whatsoever.** Every Prowler finding's "Status
  Extended" field is a single terse technical sentence. No "what would an
  attacker actually do," no specific remediation beyond a generic
  `Recommendation` field.
- **A same-class false-positive risk to one we already found and fixed.**
  Prowler flagged `AWSServiceRoleForSupport` — an AWS-managed
  service-linked role — for "has Bedrock permissions but has never used
  them." This is the identical pattern to the USE-27 service-linked-role bug
  we found and excluded earlier today. Even a mature tool isn't immune to
  it; worth knowing, not something to feel behind about.

### Where I was wrong earlier today, worth recording honestly

I initially claimed Prowler likely doesn't do privilege-escalation-path
analysis. **That was incorrect.** It has a real, dedicated check:
`iam_inline_policy_allows_privilege_escalation`, which correctly evaluated
and passed `taskflow-ci-deploy-role` (the role genuinely doesn't allow
escalation). I couldn't determine its relative *depth* versus ours from one
passing result — that needs an actual escalation-capable policy to test
both against, which this account didn't have by design.

**Rating: 9/10.** Not a 10 only because of the confirmed
service-linked-role false-positive pattern above — genuinely excellent
breadth, maturity, and compliance mapping otherwise.

---

## PMapper (Principal Mapper)

**What it is:** NCC Group's specialized IAM graph-analysis tool. Models
every principal, policy, and trust relationship as a directed graph, then
simulates AWS's actual authorization logic locally to find privilege-
escalation paths — a fundamentally different method than pattern-matching
against known techniques (what both our tool and Prowler do).

**What happened running it today, in full:**
- `pip install principalmapper` — small, clean install (9 packages), no
  friction, unlike Prowler's much heavier dependency tree.
- **Broke immediately on Python 3.13** with
  `ImportError: cannot import name 'Mapping' from 'collections'` —
  `collections.Mapping`/`MutableMapping` were deprecated in Python 3.3,
  removed entirely in Python 3.10. PMapper's own code still uses the
  pre-3.10 import path. **This is a genuine, confirmed staleness problem in
  the package itself** — it would fail identically on any Python 3.10+,
  not just 3.13. Patched directly in the venv (`collections.abc` import)
  to proceed.
- **Crashed on region enumeration** with an unhandled
  `ConnectTimeoutError` on `me-south-1`'s autoscaling endpoint. Notably,
  PMapper *does* have graceful handling for most disabled/opt-in regions
  (logs "Unable to search region X... Continuing" and moves on) — but a raw
  network timeout wasn't part of the caught exception set, so it crashed
  instead of continuing. Fixed by explicitly scoping to
  `--include-regions us-east-1`, where all real infrastructure actually
  lives.
- Once past both issues: **graph built cleanly** — 6 nodes, 0 admins, 0
  edges, 8 tracked policies.
- **Privilege-escalation query returned nothing** — `pmapper --account
  111111111111 query -s "preset privesc *"` produced no output at all.

### Was this a real negative result, or a limitation of the test?

**A genuine, correct negative — but an inconclusive test of depth.** This
account was deliberately built without any actual escalation path this
time (no wildcard `sts:AssumeRole`, unlike the very first demo account).
PMapper correctly found nothing because there was genuinely nothing to
find — same honest limitation as the Prowler privesc comparison above.
**Today's testing cannot actually answer "does PMapper or our tool go
deeper on a real escalation chain"** — that requires re-running against an
account that actually has one.

### Confirmed strengths

- **Methodologically more rigorous for this specific problem than either
  other tool.** A real directed graph plus actual policy simulation, not
  pattern-matching against known technique shapes. This is a legitimate,
  structural advantage for privilege-escalation analysis specifically —
  it's the reason PMapper exists as a separate, specialized tool at all.
- When it does find something (per its own documented example output, not
  verified live today), it names the actual mechanism:
  *"user/EC2Manager can escalate privileges by accessing the administrative
  principal role/EC2Role-Admin... can use EC2 to run an instance with an
  existing instance profile..."* — a real technical trace, not just a bare
  graph.

### Confirmed weaknesses

- **Visibly the least maintained of the three tools**, demonstrated
  directly today, not assumed: a Python 3.10+ compatibility break requiring
  a manual source patch, and an unhandled crash on a routine, common
  network condition (a disabled region timing out rather than rejecting
  quickly).
- **No severity rating at all.** A finding is just "this path exists,"
  with no Critical/High/Medium framing.
- **No remediation guidance whatsoever.** It tells you a path exists; it
  never tells you what to do about it. Confirmed absent, not just
  under-emphasized.
- **The rawest output of all three tools.** A text-based graph query result
  or an unlabeled SVG — a developer's analysis tool, not something
  presentable to a non-technical founder.

**Rating: 7/10.** Excellent, genuinely superior methodology for the one
narrow problem it solves; real, demonstrated maintenance and completeness
gaps holding it back from a higher score.

---

## Our tool

**Confirmed strengths, verified against real competitor output today, not
just claimed:**
- **Plain-English narration is a genuine, uncontested differentiator.**
  Neither Prowler nor PMapper does anything close to the WHAT'S
  WRONG / WHAT AN ATTACKER DOES / HOW TO FIX structure. Confirmed by reading
  both tools' actual output side by side.
  > **Update:** this shipped as Impact / Confidence / Evidence / Next Step
  > in the actual report, not the three-section layout named above — the
  > underlying differentiator (structured, plain-English narration
  > competitors don't have) is unchanged, just refined after real use
  > showed the fix detail needed to be collapsible and the finding's own
  > confidence/evidence needed to be surfaced as distinct fields, not
  > buried in prose. Leaving the original wording above as-is rather than
  > editing it away, same reasoning as the CFN-flow note earlier in this
  > document.
- **USE-26/27's general-purpose usage analysis is broader than anything
  either competitor has** — Prowler's equivalent is scoped to one service
  (Bedrock); PMapper has no usage-staleness concept at all.
- **GuardDuty detection is reliable** where Prowler's wasn't in this run.
- **The concierge/CFN cross-account access model** — neither competitor
  ships anything comparable; both assume the operator already has direct
  credentials.

**Confirmed real gaps, found via today's comparisons, not assumed:**
- No confused-deputy / cross-service trust-policy check (Prowler has one,
  we don't).
- No true graph-based privilege-escalation simulation (PMapper's core
  method; ours is pattern-matching against known technique shapes).
- No compliance-framework mapping (CIS, PCI-DSS, SOC2, HIPAA) — Prowler
  bakes this in natively.
- 31 checks vs. Prowler's 405 — an honest, expected breadth gap for an
  early MVP.
- Our own severity scale sometimes diverges from Prowler's without a
  documented rationale (IAM-11: we say High, Prowler says Medium) — worth
  either justifying the difference explicitly or reconsidering it.

### Bugs this comparison exercise directly caused us to find and fix, today

1. **Prefix-wildcard filter gap** — `iam:Get*`/`iam:List*` were slipping
   past the "don't flag broad grants as unused" rule, which only caught
   exact `service:*` wildcards. Fixed; regression test added.
2. **Service-linked roles flagged for "never assumed, delete it."** Real
   risk: recommending deletion of an AWS-managed role something might
   silently, legitimately depend on. Fixed via path-prefix exclusion,
   confirmed against AWS's own documented `/aws-service-role/` convention.
3. **NET-03 overclaiming "all protocols"** when a rule was confirmed,
   via direct `aws ec2 describe-security-groups` output, to be
   protocol-specific (TCP only). Fixed with protocol-aware wording.

All three were found by reading real, close, skeptical output — not by
anticipating them in advance. This is the same discipline that shaped this
entire project from Day 1, and it held up under a new kind of pressure (a
direct, same-account comparison against established competitors) exactly as
it should.

**Rating: 7/10.** The verified strengths are real, not aspirational — but
it's an early-stage, single-developer MVP measured against a
years-mature, widely-deployed tool and a specialized graph-analysis tool.
That gap is expected at this stage, not a design flaw.

---

## Improvement roadmap, organized by the four areas asked about

### Simplicity

- **Genuine current advantage, worth knowing:** our tool never hit anything
  like today's SmartScreen/pip.exe blocks, Windows long-path failures, or
  Python-version incompatibilities — the entire local install is one venv
  and a `pip install -r requirements.txt`. That's a real, demonstrated
  contrast with what Prowler and PMapper put you through today.
- **Where it's currently more complex than it needs to be:** the full
  cross-account flow (Terraform testbed, CFN link generation, External ID
  handling) has a lot of moving parts for what should eventually be a
  one-click customer experience. Worth a genuine "what does day-one setup
  look like for someone who isn't you" pass before this goes to real
  strangers.

  > **Update, post-2026-07-17:** resolved, more thoroughly than this note
  > anticipated — the cross-account flow was dropped from the tool
  > entirely, not simplified. Local credentials only. See the OSS release
  > plan §1/§3.1 and `docs/TECHNICAL-EXPLAINER.md` §5. Leaving the
  > original observation above as-is rather than editing it away — it was
  > an accurate read of the tool as it existed on this date, and this is
  > a comparison document, not living documentation.
- Concretely: a single `plexavo scan` mode using only the free templated
  checks (no `--explain`, no report generation) already gives a true
  one-command "just tell me the score" experience for a first-touch demo
  — this exists now, not as a future concretely-suggested addition.

### Scanning (breadth and depth)

- **Add the confused-deputy check** — direct, concrete, found today via
  Prowler. Not hard to build: check any role/user trust policy for a
  `Service` or cross-account `AWS` principal lacking an `ExternalId` or
  `SourceAccount`/`SourceArn` condition.
- **Consider a real graph-based privilege-escalation pass**, at least as an
  optional deeper mode, rather than relying solely on the current pattern-
  matched checks (IAM-01 through IAM-06). This is the single most
  legitimate structural gap surfaced today.
- **Per-region CloudTrail enumeration**, matching Prowler's granularity,
  rather than the current account-wide LOG-22/23.
- Longer-term: a lightweight compliance-tagging layer (which checks map to
  which CIS/SOC2 controls) — not to compete with Prowler's breadth, but to
  make the existing 31 checks legible to a customer who's specifically
  asking "am I SOC2-ready," which does come up even at the startup stage.

### Findings (accuracy and calibration)

- **Revisit severity calibration against Prowler's scale deliberately**,
  not by accident. Either document explicitly why IAM-11 (2 active keys) is
  High in our tool vs Medium in Prowler's, or align it — right now it's an
  unexplained divergence, and an unexplained divergence next to a
  more-established tool reads as our number being wrong, whether it
  actually is or not.
- **Keep the "verify against real output" discipline that just found three
  more real bugs today** — this is clearly the actual mechanism that
  produces reliability here, not a one-time cleanup phase.

### UX (output and presentation)

- **The narration and report generation are the clearest, most defensible
  advantage over both competitors** — protect this rather than dilute it
  chasing Prowler's breadth.
- **A "quick wins" summary at the top of the report** — e.g., "these 4
  Critical findings all trace to one root cause; fixing it clears ~60
  points" — was identified as a real, unbuilt gap earlier this project
  (the original blueprint's "Break Point Analysis" feature). Today's
  comparison reinforces this is worth building: it's exactly the kind of
  synthesis neither Prowler nor PMapper attempts at all, and it would
  widen the UX gap rather than just maintain it.
- Consider a short "how this compares to a generic scan" framing
  *somewhere* in the product story (not necessarily the report itself) —
  today's results are genuinely good, specific material for that.
