//! Protocol-neutral enforcement: the SAME gateway core enforces native, AP2-style
//! and ACP-style Intent Mandates identically. In-scope allows; over-cap, wrong
//! merchant, expired, tampered and wrong-key all deny — regardless of protocol.

use chrono::{TimeZone, Utc};

use citadel_mandate_demo::engine::Gateway;
use citadel_mandate_demo::mandate::{sign_mandate, test_key, IntentMandate, MandateKeyRegistry};
use citadel_mandate_demo::protocol::{acp_sign_wire, ap2_sign_wire, Acp, Ap2};
use citadel_mandate_demo::scope::Charge;

const USER: &str = "alice@example.com";
const AGENT: &str = "agent-x";
const ISS: &str = "2026-01-01T00:00:00Z";
const FUT: &str = "2100-01-01T00:00:00Z";
const PAST: &str = "2000-01-01T00:00:00Z";

fn gw() -> Gateway {
    let mut r = MandateKeyRegistry::new();
    r.trust(USER, test_key(7).verifying_key());
    Gateway::new(r, test_key(200))
}

fn charge(merchant: &str, cents: u64) -> Charge {
    Charge {
        merchant: merchant.into(),
        amount_cents: cents,
        currency: "usd".into(),
    }
}

fn ap2(id: &str, cap: u64, merchants: &[&str], not_after: &str, seed: u8) -> Vec<u8> {
    ap2_sign_wire(
        id,
        USER,
        AGENT,
        cap,
        "usd",
        merchants,
        ISS,
        not_after,
        &test_key(seed),
    )
}

fn acp(id: &str, cap: u64, merchants: &[&str], expires: &str, seed: u8) -> Vec<u8> {
    acp_sign_wire(
        id,
        USER,
        AGENT,
        cap,
        "usd",
        merchants,
        ISS,
        expires,
        &test_key(seed),
    )
}

// ── AP2-style ────────────────────────────────────────────────────────

#[test]
fn ap2_in_scope_allows() {
    let w = ap2("ap2-1", 15_000, &["acme"], FUT, 7);
    assert!(gw()
        .authorize_with(&Ap2, &w, &charge("acme", 12_000))
        .is_allow());
}

#[test]
fn ap2_over_cap_denied() {
    let w = ap2("ap2-2", 15_000, &["acme"], FUT, 7);
    assert!(!gw()
        .authorize_with(&Ap2, &w, &charge("acme", 50_000))
        .is_allow());
}

#[test]
fn ap2_wrong_merchant_denied() {
    let w = ap2("ap2-3", 15_000, &["acme"], FUT, 7);
    assert!(!gw()
        .authorize_with(&Ap2, &w, &charge("evil.sh", 100))
        .is_allow());
}

#[test]
fn ap2_expired_denied() {
    let w = ap2("ap2-4", 15_000, &["acme"], PAST, 7);
    assert!(!gw()
        .authorize_with(&Ap2, &w, &charge("acme", 100))
        .is_allow());
}

#[test]
fn ap2_tampered_denied() {
    // Raise the cap after signing — the AP2 signature no longer authenticates it.
    let w = ap2("ap2-5", 15_000, &["acme"], FUT, 7);
    let mut v: serde_json::Value = serde_json::from_slice(&w).unwrap();
    v["max_amount"] = serde_json::json!(99_999_999u64);
    let tampered = serde_json::to_vec(&v).unwrap();
    assert!(!gw()
        .authorize_with(&Ap2, &tampered, &charge("acme", 100))
        .is_allow());
}

#[test]
fn ap2_wrong_key_denied() {
    let w = ap2("ap2-6", 15_000, &["acme"], FUT, 9); // attacker key
    assert!(!gw()
        .authorize_with(&Ap2, &w, &charge("acme", 100))
        .is_allow());
}

// ── ACP-style ────────────────────────────────────────────────────────

#[test]
fn acp_in_scope_allows() {
    let w = acp("acp-1", 15_000, &["acme"], FUT, 7);
    assert!(gw()
        .authorize_with(&Acp, &w, &charge("acme", 12_000))
        .is_allow());
}

#[test]
fn acp_over_cap_denied() {
    let w = acp("acp-2", 15_000, &["acme"], FUT, 7);
    assert!(!gw()
        .authorize_with(&Acp, &w, &charge("acme", 50_000))
        .is_allow());
}

#[test]
fn acp_tampered_denied() {
    let w = acp("acp-3", 15_000, &["acme"], FUT, 7);
    let mut v: serde_json::Value = serde_json::from_slice(&w).unwrap();
    // Tamper the nested limit.
    v["limit"]["max_cents"] = serde_json::json!(99_999_999u64);
    let tampered = serde_json::to_vec(&v).unwrap();
    assert!(!gw()
        .authorize_with(&Acp, &tampered, &charge("acme", 100))
        .is_allow());
}

#[test]
fn acp_wrong_key_denied() {
    let w = acp("acp-4", 15_000, &["acme"], FUT, 9);
    assert!(!gw()
        .authorize_with(&Acp, &w, &charge("acme", 100))
        .is_allow());
}

// ── One core, three protocols ────────────────────────────────────────

#[test]
fn one_core_enforces_native_ap2_and_acp() {
    let mut g = gw();

    // native wire
    let native = sign_mandate(
        &IntentMandate {
            mandate_id: "native-1".into(),
            user_id: USER.into(),
            agent_id: AGENT.into(),
            intent_description: "native".into(),
            max_amount_cents: 15_000,
            currency: "usd".into(),
            allowed_merchants: vec!["acme".into()],
            created_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            expires_at: Utc.with_ymd_and_hms(2100, 1, 1, 0, 0, 0).unwrap(),
        },
        &test_key(7),
    );

    assert!(
        g.authorize(&native, &charge("acme", 100)).is_allow(),
        "native"
    );
    assert!(
        g.authorize_with(
            &Ap2,
            &ap2("ap2-x", 15_000, &["acme"], FUT, 7),
            &charge("acme", 100)
        )
        .is_allow(),
        "ap2"
    );
    assert!(
        g.authorize_with(
            &Acp,
            &acp("acp-x", 15_000, &["acme"], FUT, 7),
            &charge("acme", 100)
        )
        .is_allow(),
        "acp"
    );

    // The same core counted all three allows.
    assert_eq!(g.metrics.allowed, 3);
    assert!(g.audit.verify(), "single audit chain spans all protocols");
}
