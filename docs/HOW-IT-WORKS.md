# How This Works — Plain English

No jargon, no assumed knowledge. If you've ever wondered "is our AWS
account actually safe, or are we just hoping it is?" — this is for you.

## The problem, in one paragraph

Most startups run their entire company on AWS but nobody on the team is
a security expert. Settings get left on defaults. A test account
someone made two years ago still has full admin power and nobody
remembers why. A database is quietly reachable from the entire
internet because a checkbox got left unchecked. Nobody's ignoring
security on purpose — there's just genuinely no one whose job it is to
notice these things, and checking manually takes real security
expertise most small teams don't have in-house.

## What this tool actually does

It looks at an AWS account the same way an experienced security
engineer would — checking 31 specific, well-known ways these accounts
go wrong — and turns what it finds into something a founder can
actually read and act on: a score out of 100, and for each problem, a
plain explanation of what's wrong, what a hacker would actually do with
it, and the exact command to fix it.

## A full walkthrough, with a real scenario

Let's say Kaveesha knows Priya, who runs a small startup called
Loopwave — five people, an app built on AWS, nobody on the team knows
much about cloud security. He offers to check her AWS account for free,
as part of validating this tool.

### Step 1 — Priya doesn't hand over a password

This is usually the first worry, and it's a reasonable one — "why would
I give a stranger the keys to our AWS account?" She doesn't. Kaveesha
sends her a link. Nothing more.

### Step 2 — She clicks it, in her own account

The link takes her to a page, inside AWS's own website (not something
Kaveesha built or controls), that shows exactly what's about to happen
— in plain text, nothing hidden. It's about to create one narrow
"viewing window" into her account. That window can only *look* at
things — list users, check settings, read configurations. It cannot
create, change, or delete anything, ever. Think of it like giving
someone a security camera feed of your office, not a key to the door.

### Step 3 — She clicks "Create," and it's done in seconds

AWS builds that viewing window automatically. It shows her one piece of
text — a long string that identifies the window it just made. She
copies that and sends it back to Kaveesha, the same way she'd send any
other message.

**Here's the important part for trust:** that viewing window only works
for Kaveesha's specific account, and only because a private, one-time
code came bundled with her link. Even if someone else somehow saw the
text she sent back, they couldn't use it themselves. And she can delete
the whole thing, instantly, any time she wants — cutting off access
completely, no waiting, no asking permission.

### Step 4 — Kaveesha runs the scan

Using that one piece of text, the tool logs in — temporarily, for at
most an hour — and works through its checklist:

- Does anyone have more power over the account than they actually need?
- Is there a way someone with low-level access could sneak their way up
  to full control?
- Are any servers or databases directly reachable from the public
  internet when they shouldn't be?
- Is anything meant to be private actually sitting open for anyone to
  read?
- Is data being stored securely, or in plain, readable form?
- If someone did break in, would anyone even know?
- Are there permissions granted to people or systems that never
  actually get used — extra risk sitting around for no reason?

### Step 5 — The results turn into something Priya can actually read

Not a wall of error codes. A score — say, 62 out of 100 — and for each
real issue found, three things in plain language: what's wrong, what a
hacker would specifically do with it, and the exact fix, ready to
copy and paste. Kaveesha sends her a proper document, not a screenshot
of a terminal.

### Step 6 — Priya reads it and knows what to do

She doesn't need to understand AWS deeply. She (or whoever handles
their infrastructure) can just follow the fix instructions one at a
time. If she ever wants to double-check something, she can go back to
that stack she created and see it's still there, still narrow, still
revocable in one click.

## Why this is different from "just Google it"

Free checklists exist. So do generic AI chatbots you could paste
questions into. What this does that those can't: it actually **looks at
the real account** — not a hypothetical, not a general best-practices
list — and only tells you about things that are genuinely,
specifically true about *your* setup, verified against real AWS data,
not guessed.

## The honest limits

This isn't a replacement for an actual security team at a larger
company, and it says so — it's built specifically for teams too small
to have one yet. A few of its checks have known, stated blind spots
(documented plainly in the project's own technical files) rather than
pretending to catch absolutely everything. What it does check, it
checks for real, against your real account, not a simulation.
