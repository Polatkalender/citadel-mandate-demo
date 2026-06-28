#![no_main]
//! Fuzz the mandate verifier with arbitrary bytes. The invariant: `verify_signed`
//! must NEVER panic on attacker-controlled input — it returns a Deny/Err instead.

use libfuzzer_sys::fuzz_target;

use citadel_mandate_demo::mandate::{test_key, verify_signed, MandateKeyRegistry};

fuzz_target!(|data: &[u8]| {
    let mut registry = MandateKeyRegistry::new();
    registry.trust("alice@example.com", test_key(7).verifying_key());
    // Result intentionally ignored: we only assert the absence of panics/UB.
    let _ = verify_signed(data, &registry);
});
