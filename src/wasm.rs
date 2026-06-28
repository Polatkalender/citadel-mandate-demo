//! Browser playground bindings (wasm-bindgen).
//!
//! Exposes the *real* verification + scope core to JavaScript so the playground
//! runs the actual Rust logic in the browser. Deterministic by design: signing
//! and verification need no RNG, and time is passed in (`now_unix`) rather than
//! read from a clock — so this compiles and runs on `wasm32` with no extra deps.

use chrono::DateTime;
use wasm_bindgen::prelude::*;

use crate::mandate::{sign_mandate, test_key, verify_signed, IntentMandate, MandateKeyRegistry};
use crate::scope::{check_scope, Charge};

fn ts(secs: i64) -> DateTime<chrono::Utc> {
    DateTime::from_timestamp(secs, 0).unwrap_or_else(|| DateTime::from_timestamp(0, 0).unwrap())
}

/// Run a tweakable mandate + charge through verify → scope and return a JSON
/// string: `{ decision, reason, token_id, canonical }`. The mandate is signed
/// in-wasm with the demo's trusted "alice" key (seed 7); `tamper` corrupts it
/// after signing to demonstrate the signature check.
#[wasm_bindgen]
pub fn decide(
    cap_cents: u64,
    allowed_merchants_csv: &str,
    charge_merchant: &str,
    charge_cents: u64,
    expires_unix: i64,
    now_unix: i64,
    tamper: bool,
) -> String {
    let merchants: Vec<String> = allowed_merchants_csv
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();

    let mandate = IntentMandate {
        mandate_id: "im_playground".into(),
        user_id: "alice@example.com".into(),
        agent_id: "agent-x".into(),
        intent_description: "playground".into(),
        max_amount_cents: cap_cents,
        currency: "usd".into(),
        allowed_merchants: merchants,
        created_at: ts(0),
        expires_at: ts(expires_unix),
    };
    let canonical = String::from_utf8_lossy(&mandate.signed_payload()).to_string();

    // Sign with the trusted key; optionally tamper after signing.
    let mut wire = sign_mandate(&mandate, &test_key(7));
    if tamper {
        if let Ok(mut v) = serde_json::from_slice::<serde_json::Value>(&wire) {
            v["max_amount_cents"] = serde_json::json!(cap_cents.saturating_add(1_000_000));
            wire = serde_json::to_vec(&v).unwrap_or(wire);
        }
    }

    let mut registry = MandateKeyRegistry::new();
    registry.trust("alice@example.com", test_key(7).verifying_key());

    // 1. verify
    let verified = match verify_signed(&wire, &registry) {
        Ok(m) => m,
        Err(e) => return out("deny", &e.to_string(), None, &canonical),
    };
    // 2. scope (time passed in, not read from a clock)
    let charge = Charge {
        merchant: charge_merchant.to_string(),
        amount_cents: charge_cents,
        currency: "usd".into(),
    };
    if let Err(reason) = check_scope(&verified, &charge, ts(now_unix)) {
        return out("deny", &reason, None, &canonical);
    }
    // 3. allow -> deterministic action-bound token id (no uuid needed here)
    let action = crate::sha256(
        format!(
            "{}|{}|{}",
            charge.merchant, charge.amount_cents, charge.currency
        )
        .as_bytes(),
    );
    let token_id = format!("ct_{}", &crate::hex(&action)[..12]);
    out("allow", "", Some(&token_id), &canonical)
}

fn out(decision: &str, reason: &str, token_id: Option<&str>, canonical: &str) -> String {
    serde_json::json!({
        "decision": decision,
        "reason": reason,
        "token_id": token_id,
        "canonical": canonical,
    })
    .to_string()
}
