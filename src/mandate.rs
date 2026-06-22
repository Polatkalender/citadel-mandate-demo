//! Intent Mandate type + the genuine Ed25519 verification core.

use std::collections::HashMap;

use base64::Engine as _;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

/// A user-signed, AP2-style **Intent Mandate**: "agent `agent_id` may spend up
/// to `max_amount_cents` `currency` at `allowed_merchants` until `expires_at`."
///
/// The signature (carried out-of-band in the wire's `signature_b64`) is a
/// detached Ed25519 signature over [`IntentMandate::signed_payload`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntentMandate {
    pub mandate_id: String,
    pub user_id: String,
    pub agent_id: String,
    pub intent_description: String,
    pub max_amount_cents: u64,
    pub currency: String,
    /// Empty = any merchant the agent chooses.
    pub allowed_merchants: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl IntentMandate {
    /// The exact bytes the signature must cover: the mandate content WITHOUT the
    /// signature, serialized deterministically (fixed struct field order). The
    /// signer and the verifier hash exactly these bytes.
    pub fn signed_payload(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("IntentMandate always serializes")
    }
}

/// The on-the-wire mandate: the mandate fields plus the detached signature.
#[derive(Deserialize)]
struct Wire {
    #[serde(flatten)]
    mandate: IntentMandate,
    signature_b64: String,
}

/// Errors are deliberately coarse: every variant is a fail-closed Deny.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("malformed mandate wire: {0}")]
    Malformed(String),
    #[error("no trusted key registered for user {0}")]
    UnknownUser(String),
    #[error("signature verification failed")]
    BadSignature,
}

/// Trusted `user_id -> Ed25519 verifying key` registry.
///
/// EMPTY = no trusted keys = every mandate is denied (fail-closed).
#[derive(Default, Clone)]
pub struct MandateKeyRegistry {
    keys: HashMap<String, VerifyingKey>,
}

impl MandateKeyRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn trust(&mut self, user_id: impl Into<String>, key: VerifyingKey) {
        self.keys.insert(user_id.into(), key);
    }

    pub fn get(&self, user_id: &str) -> Option<&VerifyingKey> {
        self.keys.get(user_id)
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// Cryptographically verify a signed mandate wire against the trusted-key
/// registry, returning the parsed mandate only on success.
///
/// **FAIL-CLOSED:** a malformed wire, an unknown user, a malformed signature, or
/// a signature that does not verify all return `Err`. There is no code path that
/// returns a mandate it could not cryptographically authenticate. This is the
/// same algorithm the production gateway runs on its live decision path.
pub fn verify_signed(
    wire_json: &[u8],
    registry: &MandateKeyRegistry,
) -> Result<IntentMandate, VerifyError> {
    let wire: Wire =
        serde_json::from_slice(wire_json).map_err(|e| VerifyError::Malformed(e.to_string()))?;

    // Resolve the user's trusted key first (unknown user => deny).
    let vk = registry
        .get(&wire.mandate.user_id)
        .ok_or_else(|| VerifyError::UnknownUser(wire.mandate.user_id.clone()))?;

    // Decode + verify the detached Ed25519 signature over the canonical payload.
    let sig_bytes = B64
        .decode(wire.signature_b64.as_bytes())
        .map_err(|_| VerifyError::BadSignature)?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|_| VerifyError::BadSignature)?;
    let digest = crate::sha256(&wire.mandate.signed_payload());
    vk.verify_strict(&digest, &signature)
        .map_err(|_| VerifyError::BadSignature)?;

    Ok(wire.mandate)
}

/// Sign a mandate with the user's key, returning the wire JSON bytes
/// (mandate fields + `signature_b64`). Used by the demo and tests to mint
/// genuinely-signed mandates.
pub fn sign_mandate(mandate: &IntentMandate, sk: &SigningKey) -> Vec<u8> {
    let digest = crate::sha256(&mandate.signed_payload());
    let sig = sk.sign(&digest);
    let mut v = serde_json::to_value(mandate).expect("mandate to value");
    v.as_object_mut().unwrap().insert(
        "signature_b64".into(),
        serde_json::Value::String(B64.encode(sig.to_bytes())),
    );
    serde_json::to_vec(&v).expect("wire to vec")
}

/// Deterministic test signing key from a single seed byte. TEST ONLY —
/// `SigningKey::from_bytes([seed; 32])` is obviously not a real secret.
pub fn test_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
