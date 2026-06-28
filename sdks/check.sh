#!/usr/bin/env bash
# Cross-language proof: each SDK signs a mandate, the Rust gateway verifies it.
# A valid mandate -> ALLOW; an out-of-scope charge -> DENY. Run from anywhere.
set -uo pipefail
cd "$(dirname "$0")/.."

PY="$(command -v python || command -v python3)"
fail=0

echo "building Rust verifier (examples/verify_wire.rs)…"
cargo build -q --example verify_wire

expect_allow() { # label, wire-cmd, merchant, cents
  if eval "$2" | cargo run -q --example verify_wire -- "$3" "$4" >/dev/null; then
    echo "  ✓ $1 -> ALLOW"
  else
    echo "  ✗ $1 -> expected ALLOW, got DENY"; fail=1
  fi
}
expect_deny() { # label, wire-cmd, merchant, cents
  if eval "$2" | cargo run -q --example verify_wire -- "$3" "$4" >/dev/null 2>&1; then
    echo "  ✗ $1 -> expected DENY, got ALLOW"; fail=1
  else
    echo "  ✓ $1 -> DENY"
  fi
}

echo "TypeScript / Node SDK:"
expect_allow "valid mandate"  "node sdks/ts/sign.mjs"      acme    12000
expect_deny  "over cap"       "node sdks/ts/sign.mjs"      acme    50000
expect_deny  "wrong merchant" "node sdks/ts/sign.mjs"      evil.sh 100

echo "Python SDK:"
expect_allow "valid mandate"  "$PY sdks/python/sign.py"    acme    12000
expect_deny  "over cap"       "$PY sdks/python/sign.py"    acme    50000
expect_deny  "wrong merchant" "$PY sdks/python/sign.py"    evil.sh 100

if [ "$fail" -eq 0 ]; then echo "ALL SDK CROSS-LANGUAGE CHECKS PASSED"; else echo "SOME CHECKS FAILED"; fi
exit $fail
