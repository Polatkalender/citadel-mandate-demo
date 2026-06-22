//! End-to-end enforcement tests — the five scenarios as hard assertions.
//!
//! These prove the demo shows REAL fail-closed behaviour: the gateway actually
//! verifies Ed25519 signatures and denies on genuine crypto / scope failures,
//! not a scripted "DENIED" print.

use citadel_mandate_demo::engine::{Gateway, Outcome};
use citadel_mandate_demo::mandate::{test_key, MandateKeyRegistry};
use citadel_mandate_demo::scenarios::{self, TRUSTED_USER};

fn gateway() -> Gateway {
    let mut registry = MandateKeyRegistry::new();
    registry.trust(TRUSTED_USER, test_key(7).verifying_key());
    Gateway::new(registry, test_key(200))
}

#[test]
fn five_scenarios_match_expected_outcomes() {
    let mut gw = gateway();
    for s in scenarios::build_all(&test_key(7)) {
        let outcome = gw.authorize(&s.wire, &s.charge);
        assert_eq!(
            outcome.is_allow(),
            s.expect_allow,
            "scenario {:?} -> {:?}",
            s.label,
            outcome
        );
        // A Deny must never carry a token.
        if let Outcome::Deny { .. } = outcome {
            assert!(!outcome.is_allow());
        }
    }
}

#[test]
fn only_the_valid_scenario_allows() {
    let mut gw = gateway();
    let allows = scenarios::build_all(&test_key(7))
        .into_iter()
        .filter(|s| gw.authorize(&s.wire, &s.charge).is_allow())
        .count();
    assert_eq!(allows, 1, "exactly one scenario should ALLOW");
}

#[test]
fn every_decision_is_audited_and_chain_verifies() {
    let mut gw = gateway();
    let n = scenarios::build_all(&test_key(7)).len();
    for s in scenarios::build_all(&test_key(7)) {
        gw.authorize(&s.wire, &s.charge);
    }
    assert_eq!(gw.audit.len(), n, "one audit entry per decision");
    assert!(gw.audit.verify(), "audit hash-chain must verify");
}

#[test]
fn empty_registry_denies_even_a_valid_signature() {
    // Fail-closed: with no trusted keys, a perfectly-signed mandate is denied.
    let mut gw = Gateway::new(MandateKeyRegistry::new(), test_key(200));
    let valid = scenarios::build_all(&test_key(7)).remove(0);
    assert!(!gw.authorize(&valid.wire, &valid.charge).is_allow());
}

#[test]
fn wrong_signing_key_is_rejected() {
    // A mandate signed by a key the registry does not map to this user -> deny.
    let mut registry = MandateKeyRegistry::new();
    registry.trust(TRUSTED_USER, test_key(7).verifying_key());
    let mut gw = Gateway::new(registry, test_key(200));
    // Sign the (otherwise valid) scenarios with an attacker key (seed 9).
    let attacker_scenarios = scenarios::build_all(&test_key(9));
    let valid_shape = attacker_scenarios.into_iter().next().unwrap();
    assert!(!gw
        .authorize(&valid_shape.wire, &valid_shape.charge)
        .is_allow());
}
