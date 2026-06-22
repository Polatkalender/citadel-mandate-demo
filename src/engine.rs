//! The enforcement pipeline: verify signature -> check scope -> audit + token.
//!
//! This is the whole point of the demo, in one place. Every Deny path is
//! fail-closed and is written to the audit log; a DPoP-style token is minted
//! ONLY on Allow.

use chrono::Utc;
use ed25519_dalek::SigningKey;

use crate::audit::AuditLog;
use crate::mandate::{verify_signed, MandateKeyRegistry};
use crate::scope::{check_scope, Charge};
use crate::token;

/// The outcome of an authorization. A Deny never carries a token.
#[derive(Debug, Clone)]
pub enum Outcome {
    Allow { token_id: String, audit_seq: u64 },
    Deny { reason: String, audit_seq: u64 },
}

impl Outcome {
    pub fn is_allow(&self) -> bool {
        matches!(self, Outcome::Allow { .. })
    }
}

/// A minimal enforcement gateway: a trusted-key registry, a hash-chained audit
/// log, and the gateway's own signing key for tokens.
pub struct Gateway {
    pub registry: MandateKeyRegistry,
    pub audit: AuditLog,
    signing_key: SigningKey,
}

impl Gateway {
    pub fn new(registry: MandateKeyRegistry, signing_key: SigningKey) -> Self {
        Self {
            registry,
            audit: AuditLog::new(),
            signing_key,
        }
    }

    /// Run a mandate + charge through the pipeline. Returns [`Outcome`] and
    /// always records exactly one audit entry.
    pub fn authorize(&mut self, wire_json: &[u8], charge: &Charge) -> Outcome {
        // 1. Cryptographic verification (fail-closed).
        let mandate = match verify_signed(wire_json, &self.registry) {
            Ok(m) => m,
            Err(e) => {
                let seq = self.audit.append(format!("DENY verify: {e}"));
                return Outcome::Deny {
                    reason: e.to_string(),
                    audit_seq: seq,
                };
            }
        };

        // 2. Scope + limit enforcement (fail-closed).
        if let Err(reason) = check_scope(&mandate, charge, Utc::now()) {
            let seq = self
                .audit
                .append(format!("DENY scope [{}]: {reason}", mandate.mandate_id));
            return Outcome::Deny {
                reason,
                audit_seq: seq,
            };
        }

        // 3. Allow -> mint an action-bound token, then audit.
        let action_hash = crate::sha256(
            format!(
                "{}|{}|{}",
                charge.merchant, charge.amount_cents, charge.currency
            )
            .as_bytes(),
        );
        let tok = token::mint(&self.signing_key, &mandate.agent_id, &action_hash, 300);
        let seq = self.audit.append(format!(
            "ALLOW [{}] {} {}c {} token={}",
            mandate.mandate_id, charge.merchant, charge.amount_cents, charge.currency, tok.id
        ));
        Outcome::Allow {
            token_id: tok.id,
            audit_seq: seq,
        }
    }
}
