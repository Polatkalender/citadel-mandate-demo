//! The enforcement pipeline: verify signature -> check scope -> budget -> audit + token.
//!
//! This is the whole point of the demo, in one place. Every Deny path is
//! fail-closed and is written to the audit log; a DPoP-style token is minted
//! ONLY on Allow.

use std::collections::HashMap;

use chrono::Utc;
use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::audit::AuditLog;
use crate::mandate::{IntentMandate, MandateKeyRegistry};
use crate::protocol::{MandateAdapter, Native};
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

/// Decision counters, exposed for observability (e.g. a Prometheus endpoint).
#[derive(Default, Clone, Debug)]
pub struct Metrics {
    pub allowed: u64,
    pub denied: u64,
}

impl Metrics {
    /// Render as Prometheus text exposition.
    pub fn prometheus(&self) -> String {
        format!(
            "# HELP citadel_decisions_total Authorization decisions by outcome.\n\
             # TYPE citadel_decisions_total counter\n\
             citadel_decisions_total{{decision=\"allow\"}} {}\n\
             citadel_decisions_total{{decision=\"deny\"}} {}\n",
            self.allowed, self.denied
        )
    }
}

/// A minimal enforcement gateway: a trusted-key registry, a hash-chained audit
/// log, the gateway's own signing key for tokens, per-mandate spend tracking,
/// and decision metrics.
pub struct Gateway {
    pub registry: MandateKeyRegistry,
    pub audit: AuditLog,
    pub metrics: Metrics,
    signing_key: SigningKey,
    /// Cumulative cents authorized per `mandate_id` — turns a mandate into a
    /// BUDGET, so replays and repeated charges accumulate against the cap.
    spent: HashMap<String, u64>,
}

impl Gateway {
    pub fn new(registry: MandateKeyRegistry, signing_key: SigningKey) -> Self {
        Self {
            registry,
            audit: AuditLog::new(),
            metrics: Metrics::default(),
            signing_key,
            spent: HashMap::new(),
        }
    }

    /// The public key a resource server uses to verify tokens this gateway mints.
    pub fn token_verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    fn deny(&mut self, log: String, reason: String) -> Outcome {
        let seq = self.audit.append(log);
        self.metrics.denied += 1;
        Outcome::Deny {
            reason,
            audit_seq: seq,
        }
    }

    /// Run a mandate + charge through the pipeline using the demo's native wire
    /// format. Returns [`Outcome`] and always records exactly one audit entry.
    pub fn authorize(&mut self, wire_json: &[u8], charge: &Charge) -> Outcome {
        self.authorize_with(&Native, wire_json, charge)
    }

    /// Same pipeline, but the wire is parsed and verified by a protocol
    /// [`MandateAdapter`] (AP2, ACP, …). The enforcement core — scope, budget,
    /// audit, token — is identical regardless of source protocol. This is the
    /// "neutral control plane" in one method.
    pub fn authorize_with<A: MandateAdapter>(
        &mut self,
        adapter: &A,
        wire_json: &[u8],
        charge: &Charge,
    ) -> Outcome {
        // 1. Protocol-specific parse + cryptographic verification (fail-closed).
        match adapter.parse_verify(wire_json, &self.registry) {
            Ok(mandate) => self.enforce(mandate, charge),
            Err(e) => self.deny(
                format!("DENY verify[{}]: {e}", adapter.name()),
                e.to_string(),
            ),
        }
    }

    /// Scope -> budget -> token -> audit, on an already-verified neutral mandate.
    fn enforce(&mut self, mandate: IntentMandate, charge: &Charge) -> Outcome {
        // 2. Scope enforcement — per-charge cap, merchant, currency, expiry.
        if let Err(reason) = check_scope(&mandate, charge, Utc::now()) {
            return self.deny(
                format!("DENY scope [{}]: {reason}", mandate.mandate_id),
                reason,
            );
        }

        // 3. Budget — cumulative spend under this mandate must not exceed the cap.
        // This is what makes replays and repeated charges fail-closed: the mandate
        // is a budget, not an unlimited standing authorization.
        let prior = *self.spent.get(&mandate.mandate_id).unwrap_or(&0);
        let prospective = prior.saturating_add(charge.amount_cents);
        if prospective > mandate.max_amount_cents {
            let reason = format!(
                "over cumulative budget: {}c spent+now > {}c cap",
                prospective, mandate.max_amount_cents
            );
            return self.deny(
                format!("DENY budget [{}]: {reason}", mandate.mandate_id),
                reason,
            );
        }

        // 4. Allow -> mint an action-bound token, record spend, audit.
        let action_hash = crate::sha256(
            format!(
                "{}|{}|{}",
                charge.merchant, charge.amount_cents, charge.currency
            )
            .as_bytes(),
        );
        let tok = token::mint(&self.signing_key, &mandate.agent_id, &action_hash, 300);
        self.spent.insert(mandate.mandate_id.clone(), prospective);
        let seq = self.audit.append(format!(
            "ALLOW [{}] {} {}c {} token={} (budget {}/{}c)",
            mandate.mandate_id,
            charge.merchant,
            charge.amount_cents,
            charge.currency,
            tok.id,
            prospective,
            mandate.max_amount_cents
        ));
        self.metrics.allowed += 1;
        Outcome::Allow {
            token_id: tok.id,
            audit_seq: seq,
        }
    }
}
