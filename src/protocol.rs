//! Protocol adapters — the "neutral control plane" in code.
//!
//! Different agent-payment protocols carry the same authority ("agent X may
//! spend up to N at these merchants until T") in different wire shapes. An
//! adapter parses a protocol-specific wire, verifies its own detached Ed25519
//! signature over its own canonical bytes, and maps it onto the single neutral
//! [`IntentMandate`]. The [`crate::engine::Gateway`] then enforces scope, budget,
//! audit and token identically — regardless of which protocol the mandate came
//! from.
//!
//! Shapes here are realistic *approximations* of AP2 and ACP Intent Mandates —
//! enough to demonstrate protocol-neutral enforcement. This is NOT certified
//! W3C VC / JWS interop.

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};

use crate::mandate::{
    verify_detached, verify_signed, IntentMandate, MandateKeyRegistry, VerifyError,
};

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

/// An adapter that turns a protocol-specific signed wire into a verified,
/// neutral [`IntentMandate`].
pub trait MandateAdapter {
    fn name(&self) -> &'static str;
    fn parse_verify(
        &self,
        wire: &[u8],
        registry: &MandateKeyRegistry,
    ) -> Result<IntentMandate, VerifyError>;
}

fn parse_rfc3339(s: &str) -> Result<DateTime<Utc>, VerifyError> {
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|e| VerifyError::Malformed(format!("bad timestamp: {e}")))
}

fn sign_b64(canonical: &[u8], sk: &SigningKey) -> String {
    use base64::Engine as _;
    let sig = sk.sign(&crate::sha256(canonical));
    B64.encode(sig.to_bytes())
}

// ── Native (the demo's own canonical wire) ───────────────────────────

pub struct Native;

impl MandateAdapter for Native {
    fn name(&self) -> &'static str {
        "native"
    }
    fn parse_verify(
        &self,
        wire: &[u8],
        registry: &MandateKeyRegistry,
    ) -> Result<IntentMandate, VerifyError> {
        verify_signed(wire, registry)
    }
}

// ── AP2-style Intent Mandate ─────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct Ap2Body {
    ap2_version: String,
    mandate_type: String,
    mandate_id: String,
    principal: String,
    agent: String,
    max_amount: u64,
    currency: String,
    allowed_merchants: Vec<String>,
    issued_at: String,
    not_after: String,
}

#[derive(Deserialize)]
struct Ap2Wire {
    #[serde(flatten)]
    body: Ap2Body,
    signature: String,
}

pub struct Ap2;

impl MandateAdapter for Ap2 {
    fn name(&self) -> &'static str {
        "ap2"
    }
    fn parse_verify(
        &self,
        wire: &[u8],
        registry: &MandateKeyRegistry,
    ) -> Result<IntentMandate, VerifyError> {
        let w: Ap2Wire =
            serde_json::from_slice(wire).map_err(|e| VerifyError::Malformed(e.to_string()))?;
        let canonical =
            serde_json::to_vec(&w.body).map_err(|e| VerifyError::Malformed(e.to_string()))?;
        verify_detached(&w.body.principal, &canonical, &w.signature, registry)?;
        Ok(IntentMandate {
            mandate_id: w.body.mandate_id,
            user_id: w.body.principal,
            agent_id: w.body.agent,
            intent_description: format!("ap2:{}", w.body.mandate_type),
            max_amount_cents: w.body.max_amount,
            currency: w.body.currency,
            allowed_merchants: w.body.allowed_merchants,
            created_at: parse_rfc3339(&w.body.issued_at)?,
            expires_at: parse_rfc3339(&w.body.not_after)?,
        })
    }
}

/// Mint a signed AP2-style Intent Mandate wire (for demos and tests).
#[allow(clippy::too_many_arguments)]
pub fn ap2_sign_wire(
    mandate_id: &str,
    principal: &str,
    agent: &str,
    max_amount: u64,
    currency: &str,
    allowed_merchants: &[&str],
    issued_at: &str,
    not_after: &str,
    sk: &SigningKey,
) -> Vec<u8> {
    let body = Ap2Body {
        ap2_version: "0.1".into(),
        mandate_type: "intent".into(),
        mandate_id: mandate_id.into(),
        principal: principal.into(),
        agent: agent.into(),
        max_amount,
        currency: currency.into(),
        allowed_merchants: allowed_merchants.iter().map(|s| s.to_string()).collect(),
        issued_at: issued_at.into(),
        not_after: not_after.into(),
    };
    let canonical = serde_json::to_vec(&body).expect("ap2 body serializes");
    let signature = sign_b64(&canonical, sk);
    let mut v = serde_json::to_value(&body).expect("ap2 body to value");
    v.as_object_mut()
        .unwrap()
        .insert("signature".into(), serde_json::Value::String(signature));
    serde_json::to_vec(&v).expect("ap2 wire to vec")
}

// ── ACP-style Intent Mandate (different, nested shape) ────────────────

#[derive(Serialize, Deserialize)]
struct AcpLimit {
    max_cents: u64,
    currency: String,
    merchants: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct AcpBody {
    protocol: String,
    id: String,
    buyer: String,
    agent_id: String,
    limit: AcpLimit,
    issued_at: String,
    expires_at: String,
}

#[derive(Deserialize)]
struct AcpWire {
    #[serde(flatten)]
    body: AcpBody,
    signature: String,
}

pub struct Acp;

impl MandateAdapter for Acp {
    fn name(&self) -> &'static str {
        "acp"
    }
    fn parse_verify(
        &self,
        wire: &[u8],
        registry: &MandateKeyRegistry,
    ) -> Result<IntentMandate, VerifyError> {
        let w: AcpWire =
            serde_json::from_slice(wire).map_err(|e| VerifyError::Malformed(e.to_string()))?;
        let canonical =
            serde_json::to_vec(&w.body).map_err(|e| VerifyError::Malformed(e.to_string()))?;
        verify_detached(&w.body.buyer, &canonical, &w.signature, registry)?;
        Ok(IntentMandate {
            mandate_id: w.body.id,
            user_id: w.body.buyer,
            agent_id: w.body.agent_id,
            intent_description: format!("acp:{}", w.body.protocol),
            max_amount_cents: w.body.limit.max_cents,
            currency: w.body.limit.currency,
            allowed_merchants: w.body.limit.merchants,
            created_at: parse_rfc3339(&w.body.issued_at)?,
            expires_at: parse_rfc3339(&w.body.expires_at)?,
        })
    }
}

/// Mint a signed ACP-style Intent Mandate wire (for demos and tests).
#[allow(clippy::too_many_arguments)]
pub fn acp_sign_wire(
    id: &str,
    buyer: &str,
    agent_id: &str,
    max_cents: u64,
    currency: &str,
    merchants: &[&str],
    issued_at: &str,
    expires_at: &str,
    sk: &SigningKey,
) -> Vec<u8> {
    let body = AcpBody {
        protocol: "acp".into(),
        id: id.into(),
        buyer: buyer.into(),
        agent_id: agent_id.into(),
        limit: AcpLimit {
            max_cents,
            currency: currency.into(),
            merchants: merchants.iter().map(|s| s.to_string()).collect(),
        },
        issued_at: issued_at.into(),
        expires_at: expires_at.into(),
    };
    let canonical = serde_json::to_vec(&body).expect("acp body serializes");
    let signature = sign_b64(&canonical, sk);
    let mut v = serde_json::to_value(&body).expect("acp body to value");
    v.as_object_mut()
        .unwrap()
        .insert("signature".into(), serde_json::Value::String(signature));
    serde_json::to_vec(&v).expect("acp wire to vec")
}
