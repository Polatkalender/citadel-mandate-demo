//! Scope + limit enforcement: does a concrete charge fall within the mandate?

use chrono::{DateTime, Utc};

use crate::mandate::IntentMandate;

/// A concrete payment the agent wants to make under a mandate.
#[derive(Debug, Clone)]
pub struct Charge {
    pub merchant: String,
    pub amount_cents: u64,
    pub currency: String,
}

/// Enforce the mandate's scope on a charge.
///
/// **FAIL-CLOSED:** any violation returns `Err(reason)`. Mirrors the gateway's
/// L2 scope + L3 limit checks (expiry, currency, amount cap, merchant allowlist).
pub fn check_scope(
    mandate: &IntentMandate,
    charge: &Charge,
    now: DateTime<Utc>,
) -> Result<(), String> {
    if now >= mandate.expires_at {
        return Err(format!(
            "mandate expired {}",
            mandate.expires_at.format("%Y-%m-%d")
        ));
    }
    if charge.currency.to_lowercase() != mandate.currency.to_lowercase() {
        return Err(format!(
            "currency mismatch: {} != {}",
            charge.currency, mandate.currency
        ));
    }
    if charge.amount_cents > mandate.max_amount_cents {
        return Err(format!(
            "over cap: {}c > {}c",
            charge.amount_cents, mandate.max_amount_cents
        ));
    }
    if !mandate.allowed_merchants.is_empty()
        && !mandate
            .allowed_merchants
            .iter()
            .any(|m| m == &charge.merchant)
    {
        return Err(format!("merchant not in allowlist: {}", charge.merchant));
    }
    Ok(())
}
