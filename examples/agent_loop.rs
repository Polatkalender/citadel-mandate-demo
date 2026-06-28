//! "Drop it in front of your agent" — a tiny shopping agent that asks the
//! gateway to authorize each payment BEFORE it spends. ALLOW → it pays;
//! DENY → it's blocked. The agent can never spend outside what the user signed.
//!
//! Run:  cargo run --example agent_loop

use chrono::{TimeZone, Utc};

use citadel_mandate_demo::engine::{Gateway, Outcome};
use citadel_mandate_demo::mandate::{sign_mandate, test_key, IntentMandate, MandateKeyRegistry};
use citadel_mandate_demo::scope::Charge;

const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const DIM: &str = "\x1b[2m";
const RESET: &str = "\x1b[0m";

fn main() {
    // The gateway trusts the user "alice" (her Ed25519 public key).
    let mut registry = MandateKeyRegistry::new();
    registry.trust("alice@example.com", test_key(7).verifying_key());
    let mut gw = Gateway::new(registry, test_key(200));

    // Alice signed one mandate: the agent may spend up to $150 at acme-store.
    let mandate = IntentMandate {
        mandate_id: "im_shopping".into(),
        user_id: "alice@example.com".into(),
        agent_id: "shopping-agent".into(),
        intent_description: "weekly groceries".into(),
        max_amount_cents: 15_000,
        currency: "usd".into(),
        allowed_merchants: vec!["acme-store".into()],
        created_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        expires_at: Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap(),
    };
    let wire = sign_mandate(&mandate, &test_key(7));

    // The agent's shopping plan: (merchant, dollars, note).
    let plan = [
        ("acme-store", 40, "milk + eggs"),
        ("acme-store", 80, "weekly box"),
        (
            "acme-store",
            60,
            "would push the total to $180 — over the $150 cap",
        ),
        ("sketchy.io", 20, "a merchant alice never allowed"),
    ];

    println!("\nshopping-agent — every payment is checked by Citadel first");
    println!("{DIM}mandate: agent may spend ≤ $150 at acme-store{RESET}\n");

    for (merchant, dollars, note) in plan {
        let charge = Charge {
            merchant: merchant.into(),
            amount_cents: dollars * 100,
            currency: "usd".into(),
        };
        match gw.authorize(&wire, &charge) {
            // ALLOW → the agent would now call the PSP, presenting `token`.
            Outcome::Allow { token_id, .. } => {
                println!(
                    "  ${dollars:<4} {merchant:<12} {GREEN}ALLOW{RESET}  → pay  {DIM}token {token_id} · {note}{RESET}"
                );
            }
            Outcome::Deny { reason, .. } => {
                println!(
                    "  ${dollars:<4} {merchant:<12} {RED}DENY{RESET}   → blocked: {reason}  {DIM}({note}){RESET}"
                );
            }
        }
    }
    println!("\nThe agent never spent a cent outside what alice signed.\n");
}
