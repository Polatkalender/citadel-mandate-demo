"""Citadel mandate SDK (Python). Signs an Intent Mandate the gateway accepts.

The canonical bytes MUST match what the Rust verifier reconstructs:
  * field order = the struct order in _ORDER (do not reorder),
  * compact JSON (no whitespace),
  * RFC3339 UTC timestamps with 'Z', whole seconds,
  * detached Ed25519 signature over sha256(canonical).

Verify it:  python sdks/python/sign.py | cargo run -q --example verify_wire -- acme 12000

Requires: pip install cryptography
"""
import base64
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_ORDER = [
    "mandate_id",
    "user_id",
    "agent_id",
    "intent_description",
    "max_amount_cents",
    "currency",
    "allowed_merchants",
    "created_at",
    "expires_at",
]


def canonical_mandate(m: dict) -> bytes:
    """The exact bytes that get signed — struct-ordered, compact JSON."""
    ordered = {k: m[k] for k in _ORDER}
    return json.dumps(ordered, separators=(",", ":")).encode("utf-8")


def sign_mandate(mandate: dict, seed: int) -> str:
    """Sign a mandate and return the wire JSON (mandate fields + signature_b64)."""
    digest = hashlib.sha256(canonical_mandate(mandate)).digest()
    key = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    sig = key.sign(digest)  # Ed25519 over the 32-byte digest
    wire = dict(mandate)
    wire["signature_b64"] = base64.b64encode(sig).decode("ascii")
    return json.dumps(wire, separators=(",", ":"))
