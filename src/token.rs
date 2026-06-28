//! DPoP-style proof token, minted ONLY on Allow — and verifiable by a resource
//! server.
//!
//! The token binds the agent and the action hash, carries a unique `jti` and an
//! expiry, and is Ed25519-signed by the gateway. SIMPLIFIED illustration —
//! production uses RFC 9449 DPoP with enclave-bound keys.

use base64::Engine as _;
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::Deserialize;

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

/// The claims carried by a verified token.
#[derive(Debug, Clone, Deserialize)]
pub struct Claims {
    pub jti: String,
    pub agent_id: String,
    pub action_hash: String,
    pub exp: i64,
}

/// Errors are coarse and fail-closed: a token that does not fully verify is rejected.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("malformed token")]
    Malformed,
    #[error("token signature verification failed")]
    BadSignature,
    #[error("token expired")]
    Expired,
}

/// Verify a compact token against the gateway's verifying key, returning its
/// claims only if the signature is valid AND it has not expired.
///
/// FAIL-CLOSED: a malformed token, a bad signature, or an expired token all
/// return `Err`. This is what a resource server runs before honouring the token
/// (the mint → present → verify loop).
pub fn verify_token(vk: &VerifyingKey, compact: &str, now_ts: i64) -> Result<Claims, TokenError> {
    let (payload_b64, sig_b64) = compact.split_once('.').ok_or(TokenError::Malformed)?;
    let payload = B64URL
        .decode(payload_b64.as_bytes())
        .map_err(|_| TokenError::Malformed)?;
    let sig_bytes = B64URL
        .decode(sig_b64.as_bytes())
        .map_err(|_| TokenError::BadSignature)?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|_| TokenError::BadSignature)?;
    vk.verify_strict(&payload, &signature)
        .map_err(|_| TokenError::BadSignature)?;
    let claims: Claims = serde_json::from_slice(&payload).map_err(|_| TokenError::Malformed)?;
    if now_ts >= claims.exp {
        return Err(TokenError::Expired);
    }
    Ok(claims)
}
