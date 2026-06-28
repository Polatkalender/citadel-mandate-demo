//! Property-based invariants (proptest). Where `adversarial.rs` encodes specific
//! attacks, this asserts properties that must hold across *thousands* of randomly
//! generated mandates, charges and raw byte blobs — a fuzz-lite that runs in CI.

use chrono::{TimeZone, Utc};
use proptest::prelude::*;

use citadel_mandate_demo::engine::Gateway;
use citadel_mandate_demo::mandate::{sign_mandate, test_key, IntentMandate, MandateKeyRegistry};
use citadel_mandate_demo::scope::Charge;
use citadel_mandate_demo::token::{mint, verify_token};

const USER: &str = "alice@example.com";

fn gw() -> Gateway {
    let mut r = MandateKeyRegistry::new();
    r.trust(USER, test_key(7).verifying_key());
    Gateway::new(r, test_key(200))
}

fn mandate(cap: u64, merchants: Vec<String>, expired: bool) -> IntentMandate {
    let exp = if expired {
        Utc.with_ymd_and_hms(2000, 1, 1, 0, 0, 0).unwrap()
    } else {
        Utc.with_ymd_and_hms(2100, 1, 1, 0, 0, 0).unwrap()
    };
    IntentMandate {
        mandate_id: "im_prop".into(),
        user_id: USER.into(),
        agent_id: "agent".into(),
        intent_description: "prop".into(),
        max_amount_cents: cap,
        currency: "usd".into(),
        allowed_merchants: merchants,
        created_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        expires_at: exp,
    }
}

proptest! {
    // INVARIANT 1: the gateway never panics on ARBITRARY bytes — it always
    // returns a decision (and an arbitrary blob is essentially never a valid
    // signed mandate, so it must be a Deny).
    #[test]
    fn never_panics_on_arbitrary_wire(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let out = gw().authorize(&bytes, &Charge { merchant: "m".into(), amount_cents: 1, currency: "usd".into() });
        prop_assert!(!out.is_allow(), "arbitrary bytes must never be allowed");
    }

    // INVARIANT 2: for a validly-signed mandate, an ALLOW implies every scope
    // rule held — amount within cap, currency matches, merchant permitted.
    // (Contrapositive of fail-closed: nothing out of scope is ever allowed.)
    #[test]
    fn allow_implies_in_scope(
        cap in 1u64..1_000_000,
        amount in 0u64..2_000_000,
        merch_idx in 0usize..3,
        expired in any::<bool>(),
    ) {
        let merchants = vec!["acme".to_string(), "globex".to_string()];
        let charge_merchant = ["acme", "globex", "evil.sh"][merch_idx].to_string();
        let wire = sign_mandate(&mandate(cap, merchants.clone(), expired), &test_key(7));
        let charge = Charge { merchant: charge_merchant.clone(), amount_cents: amount, currency: "usd".into() };

        let out = gw().authorize(&wire, &charge);
        if out.is_allow() {
            prop_assert!(amount <= cap, "allowed over cap");
            prop_assert!(!expired, "allowed expired");
            prop_assert!(merchants.contains(&charge_merchant), "allowed out-of-allowlist merchant");
        }
    }

    // INVARIANT 3: tampering ANY signed field after signing breaks verification
    // (the signature covers every scope field).
    #[test]
    fn tampering_any_field_denies(field in 0usize..4, newval in 0u64..u64::MAX) {
        let wire = sign_mandate(&mandate(15_000, vec!["acme".into()], false), &test_key(7));
        let mut v: serde_json::Value = serde_json::from_slice(&wire).unwrap();
        let obj = v.as_object_mut().unwrap();
        match field {
            0 => { obj.insert("max_amount_cents".into(), serde_json::json!(newval)); }
            1 => { obj.insert("user_id".into(), serde_json::json!(format!("u{newval}"))); }
            2 => { obj.insert("agent_id".into(), serde_json::json!(format!("a{newval}"))); }
            _ => { obj.insert("allowed_merchants".into(), serde_json::json!(["acme", format!("x{newval}")])); }
        }
        let tampered = serde_json::to_vec(&v).unwrap();
        let out = gw().authorize(&tampered, &Charge { merchant: "acme".into(), amount_cents: 1, currency: "usd".into() });
        // user_id tampering may flip to UnknownUser; either way it must DENY.
        prop_assert!(!out.is_allow(), "tampered mandate must be denied");
    }

    // INVARIANT 4: a freshly minted token verifies; flipping any byte of the
    // compact form makes it fail (no panic, fail-closed).
    #[test]
    fn token_roundtrips_and_rejects_bitflips(seed in 1u8..255, pos in 0usize..40) {
        let sk = test_key(seed);
        let now = Utc::now().timestamp();
        let tok = mint(&sk, "agent", &[seed; 32], 300);
        prop_assert!(verify_token(&sk.verifying_key(), &tok.compact, now).is_ok());

        let mut bytes = tok.compact.clone().into_bytes();
        if pos < bytes.len() && bytes[pos] != b'.' {
            bytes[pos] ^= 0x01;
            if let Ok(flipped) = String::from_utf8(bytes) {
                prop_assert!(verify_token(&sk.verifying_key(), &flipped, now).is_err());
            }
        }
    }
}
