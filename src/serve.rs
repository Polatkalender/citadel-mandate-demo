//! Optional HTTP gateway (`citadel-mandate-demo serve`).
//!
//! A real endpoint you can put in front of an agent: POST a signed mandate plus
//! the charge it wants to make; get back allow + token, or deny + reason. The
//! server seeds one trusted test user (`alice@example.com`, signed with the
//! demo `mint` key) so it is immediately demoable.

use std::sync::{Arc, Mutex};

use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::engine::{Gateway, Outcome};
use crate::mandate::{test_key, MandateKeyRegistry};
use crate::scenarios::TRUSTED_USER;
use crate::scope::Charge;

/// Hard cap on the request body. A signed mandate + charge is well under 1 KiB;
/// 32 KiB is generous while making the bound explicit rather than relying on a
/// framework default (a deliberate DoS guard).
const MAX_BODY_BYTES: usize = 32 * 1024;

#[derive(Deserialize)]
struct AuthorizeReq {
    /// The signed mandate wire (object with the mandate fields + signature_b64).
    mandate: serde_json::Value,
    charge: ChargeDto,
}

#[derive(Deserialize)]
struct ChargeDto {
    merchant: String,
    amount_cents: u64,
    currency: String,
}

#[derive(Serialize)]
struct AuthorizeResp {
    decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_id: Option<String>,
    audit_seq: u64,
    audit_head: String,
}

pub type Shared = Arc<Mutex<Gateway>>;

async fn authorize(State(gw): State<Shared>, Json(req): Json<AuthorizeReq>) -> Response {
    let wire = serde_json::to_vec(&req.mandate).unwrap_or_default();
    let charge = Charge {
        merchant: req.charge.merchant,
        amount_cents: req.charge.amount_cents,
        currency: req.charge.currency,
    };

    // FAIL-CLOSED: a poisoned lock means a prior request panicked while holding
    // it. Rather than panic this request too (or serve from unknown state), deny
    // with 503 — never an allow.
    let mut g = match gw.lock() {
        Ok(g) => g,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "decision": "deny",
                    "reason": "gateway unavailable — fail-closed",
                })),
            )
                .into_response();
        }
    };

    let outcome = g.authorize(&wire, &charge);
    let audit_head = g.audit.head_hex();
    drop(g);

    let resp = match outcome {
        Outcome::Allow {
            token_id,
            audit_seq,
        } => AuthorizeResp {
            decision: "allow".into(),
            reason: None,
            token_id: Some(token_id),
            audit_seq,
            audit_head,
        },
        Outcome::Deny { reason, audit_seq } => AuthorizeResp {
            decision: "deny".into(),
            reason: Some(reason),
            token_id: None,
            audit_seq,
            audit_head,
        },
    };
    (StatusCode::OK, Json(resp)).into_response()
}

/// Build the gateway HTTP router (extracted so it can be tested directly).
pub fn build_router(shared: Shared) -> Router {
    Router::new()
        .route("/v1/authorize", post(authorize))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(shared)
}

/// Start the HTTP gateway on 0.0.0.0:8080 and block forever.
pub fn run_blocking() {
    let mut registry = MandateKeyRegistry::new();
    registry.trust(TRUSTED_USER, test_key(7).verifying_key());
    let gateway = Gateway::new(registry, test_key(200)); // gateway token key (TEST)
    let shared: Shared = Arc::new(Mutex::new(gateway));

    let app = build_router(shared);

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        let addr = "0.0.0.0:8080";
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .expect("bind 0.0.0.0:8080");
        println!("citadel-mandate-demo gateway listening on http://{addr}");
        println!("  POST /v1/authorize");
        println!(
            "  body: {{\"mandate\": <signed wire>, \"charge\": {{\"merchant\":..,\"amount_cents\":..,\"currency\":\"usd\"}}}}"
        );
        println!("  trusted user: {TRUSTED_USER}  (mint a request with: citadel-mandate-demo mint)");
        axum::serve(listener, app).await.expect("serve");
    });
}
