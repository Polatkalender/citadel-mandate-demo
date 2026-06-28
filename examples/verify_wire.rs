//! Cross-language oracle: read a NATIVE mandate wire (JSON) on stdin, run it
//! through the gateway against the trusted seed-7 key, print the decision.
//!
//! Used by the SDK cross-language check (an SDK signs a mandate, this Rust
//! verifier accepts or rejects it):
//!
//!   node sdks/ts/sign.mjs | cargo run -q --example verify_wire -- acme 12000
//!   python sdks/python/sign.py | cargo run -q --example verify_wire -- acme 12000
//!
//! Exit 0 = ALLOW, exit 1 = DENY.

use std::io::Read;

use citadel_mandate_demo::engine::{Gateway, Outcome};
use citadel_mandate_demo::mandate::{test_key, MandateKeyRegistry};
use citadel_mandate_demo::scope::Charge;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let merchant = args.first().cloned().unwrap_or_else(|| "acme".into());
    let amount_cents: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(12_000);

    let mut wire = Vec::new();
    std::io::stdin().read_to_end(&mut wire).expect("read stdin");

    let mut registry = MandateKeyRegistry::new();
    registry.trust("alice@example.com", test_key(7).verifying_key());
    let mut gw = Gateway::new(registry, test_key(200));

    match gw.authorize(
        &wire,
        &Charge {
            merchant,
            amount_cents,
            currency: "usd".into(),
        },
    ) {
        Outcome::Allow { token_id, .. } => {
            println!("ALLOW token={token_id}");
        }
        Outcome::Deny { reason, .. } => {
            eprintln!("DENY: {reason}");
            std::process::exit(1);
        }
    }
}
