# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** via GitHub's
"Report a vulnerability" (Security tab → Advisories) on this repository.
If that is unavailable, open an issue *asking for a private contact channel*
without disclosing details.

- You will receive an acknowledgement as soon as reasonably possible
  (best effort — this is an independently maintained open-source project,
  not a staffed security team; no SLA is promised).
- Coordinated disclosure is preferred: please allow a reasonable window
  for a fix before publishing details.
- Verified fixes are released with a changelog entry crediting the
  reporter (unless anonymity is requested).

## What this repository contains

Test vectors and conformance material, not a runtime library. A defect here is
usually a **wrong expected value** — a vector that asserts something untrue, so
that an implementation is judged conformant when it is not, or the reverse.
That is a security-relevant defect and is in scope for this policy: say which
vector, what it asserts, and what you measured instead.

## Supported versions

Only the **latest tagged release** receives fixes.

## About this policy

This file is a reporting channel, not a legal conformity statement: it exists
because a project that asks others for a reporting channel should have one.
