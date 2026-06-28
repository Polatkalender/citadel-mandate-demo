//! Throughput / latency benchmarks for the enforcement core.
//!
//! Run with: `cargo bench`. Numbers in the README are taken from this.

use chrono::{TimeZone, Utc};
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};

use citadel_mandate_demo::engine::Gateway;
use citadel_mandate_demo::mandate::{
    sign_mandate, test_key, verify_signed, IntentMandate, MandateKeyRegistry,
};
use citadel_mandate_demo::scope::Charge;

const USER: &str = "alice@example.com";

fn registry() -> MandateKeyRegistry {
    let mut r = MandateKeyRegistry::new();
    r.trust(USER, test_key(7).verifying_key());
    r
}

fn valid_wire() -> Vec<u8> {
    let m = IntentMandate {
        mandate_id: "im_bench".into(),
        user_id: USER.into(),
        agent_id: "agent".into(),
        intent_description: "bench".into(),
        max_amount_cents: 15_000,
        currency: "usd".into(),
        allowed_merchants: vec!["acme".into()],
        created_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        expires_at: Utc.with_ymd_and_hms(2100, 1, 1, 0, 0, 0).unwrap(),
    };
    sign_mandate(&m, &test_key(7))
}

fn charge() -> Charge {
    Charge {
        merchant: "acme".into(),
        amount_cents: 100,
        currency: "usd".into(),
    }
}

fn benches(c: &mut Criterion) {
    let wire = valid_wire();
    let reg = registry();

    // Just the cryptographic verification (Ed25519 + canonical hash).
    c.bench_function("verify_signed", |b| {
        b.iter(|| {
            let _ = verify_signed(black_box(&wire), black_box(&reg));
        })
    });

    // The full allow path: verify -> scope -> budget -> mint token -> audit.
    c.bench_function("authorize_allow_full_path", |b| {
        b.iter_batched(
            || {
                let mut r = MandateKeyRegistry::new();
                r.trust(USER, test_key(7).verifying_key());
                (Gateway::new(r, test_key(200)), valid_wire(), charge())
            },
            |(mut gw, w, ch)| {
                let _ = gw.authorize(black_box(&w), black_box(&ch));
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(g, benches);
criterion_main!(g);
