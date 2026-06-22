//! Adversarial / bypass suite — actively *tries* to defeat the gateway.
//!
//! Every test is a real attack attempt against the public API (no mocking of
//! the decision). A passing suite means each attack was correctly DENIED (or,
//! for the documented by-design cases, behaved exactly as specified). This is
//! the executable evidence behind the demo's "fail-closed" claim.

use chrono::{DateTime, Duration, TimeZone, Utc};

use citadel_mandate_demo::engine::{Gateway, Outcome};
use citadel_mandate_demo::mandate::{
    sign_mandate, test_key, verify_signed, IntentMandate, MandateKeyRegistry,
};
use citadel_mandate_demo::scenarios::{AGENT, MERCHANT, TRUSTED_USER};
use citadel_mandate_demo::scope::Charge;

// ── helpers ──────────────────────────────────────────────────────────

fn gw() -> Gateway {
    let mut r = MandateKeyRegistry::new();
    r.trust(TRUSTED_USER, test_key(7).verifying_key()); // alice trusts seed-7
    Gateway::new(r, test_key(200))
}

fn future() -> DateTime<Utc> {
    Utc::now() + Duration::days(365)
}

fn mandate(user: &str, max: u64, merchants: &[&str], expires: DateTime<Utc>) -> IntentMandate {
    IntentMandate {
        mandate_id: "im_adv".into(),
        user_id: user.into(),
        agent_id: AGENT.into(),
        intent_description: "adversarial".into(),
        max_amount_cents: max,
        currency: "usd".into(),
        allowed_merchants: merchants.iter().map(|s| s.to_string()).collect(),
        created_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        expires_at: expires,
    }
}

fn charge(merchant: &str, cents: u64) -> Charge {
    Charge { merchant: merchant.into(), amount_cents: cents, currency: "usd".into() }
}

/// A genuinely-signed wire for the trusted user (seed-7), $150 cap, MERCHANT.
fn signed_ok() -> Vec<u8> {
    sign_mandate(&mandate(TRUSTED_USER, 15_000, &[MERCHANT], future()), &test_key(7))
}

fn tamper<F: FnOnce(&mut serde_json::Map<String, serde_json::Value>)>(wire: &[u8], f: F) -> Vec<u8> {
    let mut v: serde_json::Value = serde_json::from_slice(wire).unwrap();
    f(v.as_object_mut().unwrap());
    serde_json::to_vec(&v).unwrap()
}

fn denied(o: &Outcome) -> bool {
    matches!(o, Outcome::Deny { .. })
}

// ═══════════════════════════════════════════════════════════════════
//  A. SIGNATURE / IDENTITY FORGERY  (all must DENY)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn a01_unsigned_mandate_denied() {
    // No signature_b64 at all → wire is structurally incomplete.
    let unsigned = serde_json::to_vec(&mandate(TRUSTED_USER, 15_000, &[MERCHANT], future())).unwrap();
    assert!(denied(&gw().authorize(&unsigned, &charge(MERCHANT, 100))));
}

#[test]
fn a02_empty_registry_denies_perfect_signature() {
    // Fail-closed: no trusted keys ⇒ even a flawless signature is rejected.
    let mut g = Gateway::new(MandateKeyRegistry::new(), test_key(200));
    assert!(denied(&g.authorize(&signed_ok(), &charge(MERCHANT, 100))));
}

#[test]
fn a03_attacker_key_denied() {
    // Signed by seed-9 (not the key registered for alice).
    let w = sign_mandate(&mandate(TRUSTED_USER, 15_000, &[MERCHANT], future()), &test_key(9));
    assert!(denied(&gw().authorize(&w, &charge(MERCHANT, 100))));
}

#[test]
fn a04_raise_cap_after_signing_denied() {
    let w = tamper(&signed_ok(), |m| {
        m.insert("max_amount_cents".into(), serde_json::json!(100_000_000u64));
    });
    assert!(denied(&gw().authorize(&w, &charge(MERCHANT, 100))));
}

#[test]
fn a05_add_merchant_after_signing_denied() {
    let w = tamper(&signed_ok(), |m| {
        m.insert("allowed_merchants".into(), serde_json::json!([MERCHANT, "evil.sh"]));
    });
    assert!(denied(&gw().authorize(&w, &charge("evil.sh", 100))));
}

#[test]
fn a06_swap_user_after_signing_denied() {
    let w = tamper(&signed_ok(), |m| {
        m.insert("user_id".into(), serde_json::json!("attacker@evil.test"));
    });
    assert!(denied(&gw().authorize(&w, &charge(MERCHANT, 100))));
}

#[test]
fn a07_swap_agent_after_signing_denied() {
    let w = tamper(&signed_ok(), |m| {
        m.insert("agent_id".into(), serde_json::json!("agent-attacker"));
    });
    assert!(denied(&gw().authorize(&w, &charge(MERCHANT, 100))));
}

#[test]
fn a08_extend_expiry_after_signing_denied() {
    let w = tamper(&signed_ok(), |m| {
        m.insert("expires_at".into(), serde_json::json!("2099-01-01T00:00:00Z"));
    });
    assert!(denied(&gw().authorize(&w, &charge(MERCHANT, 100))));
}

#[test]
fn a09_garbage_signature_denied() {
    let w = tamper(&signed_ok(), |m| {
        m.insert("signature_b64".into(), serde_json::json!("AAAA")); // wrong length
    });
    assert!(denied(&gw().authorize(&w, &charge(MERCHANT, 100))));
}

#[test]
fn a10_non_base64_signature_denied() {
    let w = tamper(&signed_ok(), |m| {
        m.insert("signature_b64".into(), serde_json::json!("!!!not base64!!!"));
    });
    assert!(denied(&gw().authorize(&w, &charge(MERCHANT, 100))));
}

#[test]
fn a11_signature_swapped_from_another_mandate_denied() {
    // Lift a valid signature off mandate A; staple it onto a different body B.
    let a = signed_ok();
    let sig = serde_json::from_slice::<serde_json::Value>(&a).unwrap()["signature_b64"].clone();
    let b = sign_mandate(&mandate(TRUSTED_USER, 999, &[MERCHANT], future()), &test_key(7));
    let forged = tamper(&b, |m| {
        m.insert("signature_b64".into(), sig);
    });
    assert!(denied(&gw().authorize(&forged, &charge(MERCHANT, 100))));
}

#[test]
fn a12_low_level_verify_rejects_all_forgeries() {
    let reg = {
        let mut r = MandateKeyRegistry::new();
        r.trust(TRUSTED_USER, test_key(7).verifying_key());
        r
    };
    // unknown user
    let u = sign_mandate(&mandate("nobody@x", 15_000, &[MERCHANT], future()), &test_key(7));
    assert!(verify_signed(&u, &reg).is_err());
    // wrong key
    let k = sign_mandate(&mandate(TRUSTED_USER, 15_000, &[MERCHANT], future()), &test_key(9));
    assert!(verify_signed(&k, &reg).is_err());
    // a valid one verifies
    assert!(verify_signed(&signed_ok(), &reg).is_ok());
}

#[test]
fn a13_duplicate_key_wire_denied() {
    // Split-view attack: inject a second max_amount_cents hoping the signature
    // check and the enforcement read different copies. serde must reject it.
    let s = String::from_utf8(signed_ok()).unwrap();
    let forged = s.replacen('{', "{\"max_amount_cents\":100000000,", 1);
    assert!(denied(&gw().authorize(forged.as_bytes(), &charge(MERCHANT, 100))));
}

#[test]
fn a14_type_confusion_denied() {
    // max_amount_cents as a string instead of a number → reject (no coercion).
    let w = tamper(&signed_ok(), |m| {
        m.insert("max_amount_cents".into(), serde_json::json!("15000"));
    });
    assert!(denied(&gw().authorize(&w, &charge(MERCHANT, 100))));
}

#[test]
fn a15_unknown_extra_field_is_inert_not_a_bypass() {
    // serde(flatten) absorbs an unknown extra field, but it is dropped before
    // both the signature check and scope enforcement — a valid mandate still
    // verifies and the extra field grants nothing.
    let w = tamper(&signed_ok(), |m| {
        m.insert("evil_extra".into(), serde_json::json!({ "admin": true }));
    });
    assert!(gw().authorize(&w, &charge(MERCHANT, 100)).is_allow());
}

// ═══════════════════════════════════════════════════════════════════
//  B. SCOPE / LIMIT EVASION
// ═══════════════════════════════════════════════════════════════════

#[test]
fn b01_amount_at_cap_allowed_over_cap_denied() {
    let w = signed_ok(); // cap 15_000
    assert!(gw().authorize(&w, &charge(MERCHANT, 15_000)).is_allow(), "at cap allowed");
    assert!(denied(&gw().authorize(&w, &charge(MERCHANT, 15_001))), "1c over cap denied");
}

#[test]
fn b02_u64_max_amount_denied_no_overflow() {
    assert!(denied(&gw().authorize(&signed_ok(), &charge(MERCHANT, u64::MAX))));
}

#[test]
fn b03_currency_mismatch_denied() {
    let g = gw();
    let w = signed_ok();
    let mut bad = charge(MERCHANT, 100);
    bad.currency = "eur".into();
    assert!(denied(&{ let mut g = g; g.authorize(&w, &bad) }));
}

#[test]
fn b04_merchant_outside_allowlist_denied() {
    assert!(denied(&gw().authorize(&signed_ok(), &charge("evil.sh", 100))));
}

#[test]
fn b05_expired_denied_valid_window_allowed() {
    // signed, but already expired
    let past = sign_mandate(
        &mandate(TRUSTED_USER, 15_000, &[MERCHANT], Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap()),
        &test_key(7),
    );
    assert!(denied(&gw().authorize(&past, &charge(MERCHANT, 100))), "expired denied");
    assert!(gw().authorize(&signed_ok(), &charge(MERCHANT, 100)).is_allow(), "in-window allowed");
}

// ═══════════════════════════════════════════════════════════════════
//  C. ROBUSTNESS  (no panic; fail-closed on junk)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn c01_malformed_json_denied_no_panic() {
    for junk in [b"{ not json".as_slice(), b"".as_slice(), b"[]".as_slice(), b"null".as_slice()] {
        assert!(denied(&gw().authorize(junk, &charge(MERCHANT, 100))));
    }
}

#[test]
fn c02_truncated_and_huge_inputs_denied_no_panic() {
    let huge = vec![b'a'; 2_000_000];
    assert!(denied(&gw().authorize(&huge, &charge(MERCHANT, 100))));
    let valid = signed_ok();
    assert!(denied(&gw().authorize(&valid[..valid.len() / 2], &charge(MERCHANT, 100))));
}

// ═══════════════════════════════════════════════════════════════════
//  D. AUDIT INTEGRITY
// ═══════════════════════════════════════════════════════════════════

#[test]
fn d01_every_decision_audited_and_chain_verifies() {
    let mut g = gw();
    g.authorize(&signed_ok(), &charge(MERCHANT, 100)); // allow
    g.authorize(&signed_ok(), &charge("evil.sh", 100)); // deny (scope)
    g.authorize(b"junk", &charge(MERCHANT, 100)); // deny (verify)
    assert_eq!(g.audit.len(), 3, "one entry per decision (allow AND deny)");
    assert!(g.audit.verify(), "hash-chain verifies");
}

// ═══════════════════════════════════════════════════════════════════
//  E. DOCUMENTED BY-DESIGN BEHAVIOUR  (not bugs — recorded for the report)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn e01_empty_allowlist_permits_any_merchant_by_design() {
    // An Intent with NO merchant restriction authorizes any merchant within cap.
    let w = sign_mandate(&mandate(TRUSTED_USER, 15_000, &[], future()), &test_key(7));
    assert!(gw().authorize(&w, &charge("anything.example", 100)).is_allow());
}

#[test]
fn e02_no_replay_protection_same_mandate_reused() {
    // The demo treats a mandate as a standing authorization: the same signed
    // mandate + charge is accepted repeatedly (no nonce / spend accumulation).
    let mut g = gw();
    let w = signed_ok();
    assert!(g.authorize(&w, &charge(MERCHANT, 100)).is_allow());
    assert!(g.authorize(&w, &charge(MERCHANT, 100)).is_allow());
    assert_eq!(g.audit.len(), 2);
}
