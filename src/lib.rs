//! # citadel-mandate-demo
//!
//! An open, runnable demo of **runtime Intent Mandate enforcement** for
//! AI-agent payments.
//!
//! Payment-delegation protocols (AP2, ACP, x402, MPP) define *how* a human
//! authorizes an agent to pay — a signed "mandate" carrying scope and limits.
//! They do not *enforce* it at runtime. This crate is the missing piece: a
//! gateway that **cryptographically verifies** the user's signed mandate and
//! **fail-closed denies** anything out of scope *before* a payment can happen.
//!
//! ## What this demo is (honest scope)
//!
//! - **Intent Mandates only.** No Cart/Payment mandates.
//! - **VC-style Ed25519** detached signatures over the canonical mandate
//!   content. This is NOT full W3C Verifiable Credential / AP2 interop.
//! - The [`audit`] log and [`token`] here are **simplified illustrations** of
//!   the production mechanisms (which add a Merkle tree + hybrid post-quantum
//!   signatures, and RFC 9449 enclave-bound DPoP, respectively).
//!
//! The verification *algorithm* itself ([`mandate::verify_signed`]) is the real
//! one, fail-closed on every error path — not a stand-in.

pub mod audit;
pub mod engine;
pub mod mandate;
pub mod protocol;
pub mod scenarios;
pub mod scope;
pub mod serve;
pub mod token;

/// SHA-256 of `bytes`.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Lowercase hex encoding (no dependency).
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
