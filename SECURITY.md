# Security policy

## Scope

This repository is an **open demonstration** of Intent Mandate enforcement. It is
deliberately simplified (see the "Honest scope" section of the
[README](README.md) and the [Security & Design report](docs/SECURITY-AND-DESIGN.md)):
the audit log and token are illustrative, and all keys here are **deterministic
test seeds** — not secrets. It is not production software.

## Reporting a vulnerability

If you find a way to make the gateway **allow** something the signed mandate does
not authorize, or to **panic / crash** it on attacker-controlled input:

- Preferred: open a [private security advisory](https://github.com/Polatkalender/citadel-mandate-demo/security/advisories/new).
- Or open a regular issue for non-sensitive findings.

Please include a minimal reproduction (a wire + charge, or a failing test). The
verifier is fuzzed (`fuzz/`) and covered by an adversarial suite
(`tests/adversarial.rs`); a great report is a new failing case for it.

## What is in scope for a report

- Signature-verification bypass (forged / tampered mandate accepted).
- Scope or budget bypass (over-cap, wrong merchant, expired, replay beyond cap).
- A panic / DoS reachable from the request path.

Out of scope: the documented simplifications (unsigned-but-tamper-evident audit,
the illustrative token, in-memory state) — these are called out as non-production
in the report, and map to hardened mechanisms in the full Citadel platform.
