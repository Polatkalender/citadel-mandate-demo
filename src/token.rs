//! DPoP-style proof token, minted ONLY on Allow.
//!
//! The token binds the agent and the action hash, carries a unique `jti` and an
//! expiry, and is Ed25519-signed by the gateway. SIMPLIFIED illustration —
//! production uses RFC 9449 DPoP with enclave-bound keys.

use base64::Engine as _;
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};

const B64URL: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

pub struct Token {
    /// Short, human-friendly id (e.g. `ct_3f9a1c2b4d5e`).
    pub id: String,
    pub jti: String,
    pub exp: i64,
    /// `base64url(claims).base64url(signature)` — verifiable with the gateway key.
    pub compact: String,
}

/// Mint a token bound to `agent_id` and `action_hash`, valid for `ttl_secs`.
pub fn mint(sk: &SigningKey, agent_id: &str, action_hash: &[u8; 32], ttl_secs: i64) -> Token {
    let jti = uuid::Uuid::new_v4().to_string();
    let exp = Utc::now().timestamp() + ttl_secs;
    let claims = serde_json::json!({
        "jti": jti,
        "agent_id": agent_id,
        "action_hash": crate::hex(action_hash),
        "exp": exp,
    });
    let payload = serde_json::to_vec(&claims).expect("claims serialize");
    let sig = sk.sign(&payload);
    let compact = format!(
        "{}.{}",
        B64URL.encode(&payload),
        B64URL.encode(sig.to_bytes())
    );
    let id = format!(
        "ct_{}",
        &crate::hex(&crate::sha256(compact.as_bytes()))[..12]
    );
    Token {
        id,
        jti,
        exp,
        compact,
    }
}
