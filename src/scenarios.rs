//! The five canonical demo scenarios, built deterministically so the demo, the
//! `mint` subcommand, and the integration tests all agree.

use chrono::{DateTime, TimeZone, Utc};
use ed25519_dalek::SigningKey;

use crate::mandate::{sign_mandate, IntentMandate};
use crate::scope::Charge;

/// The one user whose key the demo gateway trusts (signed with `test_key(7)`).
pub const TRUSTED_USER: &str = "alice@example.com";
pub const AGENT: &str = "agent-7c3f-shopping";
pub const MERCHANT: &str = "acme-store.example";

/// $150 cap, in cents.
pub const CAP_CENTS: u64 = 15_000;

fn far_future() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap()
}

fn long_past() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap()
}

fn mandate(max_cents: u64, merchants: &[&str], expires: DateTime<Utc>) -> IntentMandate {
    IntentMandate {
        mandate_id: "im_demo_0001".into(),
        user_id: TRUSTED_USER.into(),
        agent_id: AGENT.into(),
        intent_description: "weekly groceries".into(),
        max_amount_cents: max_cents,
        currency: "usd".into(),
        allowed_merchants: merchants.iter().map(|s| s.to_string()).collect(),
        created_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        expires_at: expires,
    }
}

fn charge(merchant: &str, amount_cents: u64) -> Charge {
    Charge {
        merchant: merchant.into(),
        amount_cents,
        currency: "usd".into(),
    }
}

/// A labelled scenario: a signed (or tampered) wire + the charge to test.
pub struct Scenario {
    /// Short label for the table.
    pub label: String,
    pub wire: Vec<u8>,
    pub charge: Charge,
    pub expect_allow: bool,
}

/// Build all five scenarios, signing the genuine ones with `sk`
/// (which must be `test_key(7)` — the key the demo gateway trusts).
pub fn build_all(sk: &SigningKey) -> Vec<Scenario> {
    vec![
        // 1. In-scope, validly signed -> ALLOW + token.
        Scenario {
            label: "valid mandate  ($120, cap $150)".into(),
            wire: sign_mandate(&mandate(CAP_CENTS, &[MERCHANT], far_future()), sk),
            charge: charge(MERCHANT, 12_000),
            expect_allow: true,
        },
        // 2. Tampered after signing -> signature no longer authenticates.
        Scenario {
            label: "tampered signature".into(),
            wire: tamper(sign_mandate(
                &mandate(CAP_CENTS, &[MERCHANT], far_future()),
                sk,
            )),
            charge: charge(MERCHANT, 12_000),
            expect_allow: false,
        },
        // 3. Validly signed but expired.
        Scenario {
            label: "expired mandate".into(),
            wire: sign_mandate(&mandate(CAP_CENTS, &[MERCHANT], long_past()), sk),
            charge: charge(MERCHANT, 12_000),
            expect_allow: false,
        },
        // 4. $5,000 charge against a $150 cap.
        Scenario {
            label: "$5,000 charge (cap $150)".into(),
            wire: sign_mandate(&mandate(CAP_CENTS, &[MERCHANT], far_future()), sk),
            charge: charge(MERCHANT, 500_000),
            expect_allow: false,
        },
        // 5. Merchant outside the allowlist.
        Scenario {
            label: "wrong merchant (->evil.sh)".into(),
            wire: sign_mandate(&mandate(CAP_CENTS, &[MERCHANT], far_future()), sk),
            charge: charge("evil.sh", 12_000),
            expect_allow: false,
        },
    ]
}

/// Raise `max_amount_cents` AFTER signing, so the detached signature is stale.
fn tamper(wire: Vec<u8>) -> Vec<u8> {
    let mut v: serde_json::Value = serde_json::from_slice(&wire).expect("wire json");
    v["max_amount_cents"] = serde_json::json!(100_000_000u64);
    serde_json::to_vec(&v).expect("tampered wire")
}
