"""Print a signed Intent Mandate wire (seed-7 = the gateway's trusted "alice").

    python sdks/python/sign.py | cargo run -q --example verify_wire -- acme 12000
"""
import sys

from citadel import sign_mandate

mandate = {
    "mandate_id": "im_py_sdk",
    "user_id": "alice@example.com",
    "agent_id": "agent-x",
    "intent_description": "py sdk demo",
    "max_amount_cents": 15000,
    "currency": "usd",
    "allowed_merchants": ["acme"],
    "created_at": "2026-01-01T00:00:00Z",
    "expires_at": "2030-01-01T00:00:00Z",
}

sys.stdout.write(sign_mandate(mandate, 7))
