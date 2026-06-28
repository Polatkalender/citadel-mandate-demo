# Citadel mandate SDKs

Tiny client SDKs that **sign an Intent Mandate** the Citadel gateway will accept —
so you can integrate from the languages agents are actually written in, not just Rust.

| Language | File | Crypto |
|---|---|---|
| TypeScript / Node | [`ts/citadel.mjs`](ts/citadel.mjs) | built-in `node:crypto` (zero deps) |
| Python | [`python/citadel.py`](python/citadel.py) | `cryptography` (`pip install cryptography`) |

## Use it

```bash
# Node — print a signed wire and verify it against the Rust gateway:
node sdks/ts/sign.mjs | cargo run -q --example verify_wire -- acme 12000      # -> ALLOW

# Python:
python sdks/python/sign.py | cargo run -q --example verify_wire -- acme 12000 # -> ALLOW
```

```js
import { signMandate, testSeed } from "./citadel.mjs";
const wire = signMandate({
  mandate_id: "im_1", user_id: "alice@example.com", agent_id: "agent-x",
  intent_description: "groceries", max_amount_cents: 15000, currency: "usd",
  allowed_merchants: ["acme"],
  created_at: "2026-01-01T00:00:00Z", expires_at: "2030-01-01T00:00:00Z",
}, testSeed(7));
// POST { mandate: JSON.parse(wire), charge } to /v1/authorize
```

## The canonicalization contract (why both SDKs interoperate byte-for-byte)

The gateway verifies a detached Ed25519 signature over a **canonical** form. Any
signer must produce exactly these bytes, or the signature won't verify:

1. **Field order** = `mandate_id, user_id, agent_id, intent_description,
   max_amount_cents, currency, allowed_merchants, created_at, expires_at`.
2. **Compact JSON** — no whitespace.
3. **Timestamps** — RFC 3339 UTC, whole seconds, `Z` suffix (e.g. `2026-01-01T00:00:00Z`).
4. **Signature** = Ed25519 over `sha256(canonical)`; placed in `signature_b64` (base64).
5. Amounts are integers (cents). In JS keep them `< 2^53`.

The TS and Python SDKs are verified to emit **identical canonical bytes**, and
both round-trip through the Rust verifier — see [`check.sh`](check.sh), run in CI.

> Test keys here are deterministic seeds (`seed=7` = the demo's trusted "alice").
> Obviously not real secrets — generate real Ed25519 keys for anything real.
