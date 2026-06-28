//! HTTP integration test — drives the real axum router (`build_router`) and
//! exercises the full loop: authorize -> token -> /v1/verify, plus /metrics and
//! the deny path. Locks the HTTP surface against regressions in CI.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{TimeZone, Utc};
use tower::ServiceExt; // oneshot

use citadel_mandate_demo::engine::Gateway;
use citadel_mandate_demo::mandate::{sign_mandate, test_key, IntentMandate, MandateKeyRegistry};
use citadel_mandate_demo::serve::{build_router, Shared};

const USER: &str = "alice@example.com";

fn shared() -> Shared {
    let mut r = MandateKeyRegistry::new();
    r.trust(USER, test_key(7).verifying_key());
    Arc::new(Mutex::new(Gateway::new(r, test_key(200))))
}

fn wire(cap: u64, merchants: &[&str]) -> serde_json::Value {
    let m = IntentMandate {
        mandate_id: "im_http".into(),
        user_id: USER.into(),
        agent_id: "agent-x".into(),
        intent_description: "http".into(),
        max_amount_cents: cap,
        currency: "usd".into(),
        allowed_merchants: merchants.iter().map(|s| s.to_string()).collect(),
        created_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        expires_at: Utc.with_ymd_and_hms(2100, 1, 1, 0, 0, 0).unwrap(),
    };
    serde_json::from_slice(&sign_mandate(&m, &test_key(7))).unwrap()
}

async fn post(app: axum::Router, path: &str, body: serde_json::Value) -> serde_json::Value {
    let resp = app
        .oneshot(
            Request::post(path)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn http_authorize_verify_loop_and_deny_and_metrics() {
    let gw = shared();

    // 1. authorize a valid charge -> allow + a verifiable token.
    let allow = post(
        build_router(gw.clone()),
        "/v1/authorize",
        serde_json::json!({
            "mandate": wire(15_000, &["acme"]),
            "charge": {"merchant": "acme", "amount_cents": 12_000, "currency": "usd"},
        }),
    )
    .await;
    assert_eq!(allow["decision"], "allow");
    let token = allow["token"].as_str().expect("token present").to_string();

    // 2. present that token to /v1/verify -> valid.
    let v = post(
        build_router(gw.clone()),
        "/v1/verify",
        serde_json::json!({ "token": token }),
    )
    .await;
    assert_eq!(v["valid"], true);
    assert_eq!(v["agent_id"], "agent-x");

    // 3. a garbage token -> not valid (fail-closed, no panic).
    let bad = post(
        build_router(gw.clone()),
        "/v1/verify",
        serde_json::json!({ "token": "not.a.token" }),
    )
    .await;
    assert_eq!(bad["valid"], false);

    // 4. over-cap charge -> deny, no token.
    let deny = post(
        build_router(gw.clone()),
        "/v1/authorize",
        serde_json::json!({
            "mandate": wire(15_000, &["acme"]),
            "charge": {"merchant": "acme", "amount_cents": 500_000, "currency": "usd"},
        }),
    )
    .await;
    assert_eq!(deny["decision"], "deny");
    assert!(deny.get("token").is_none() || deny["token"].is_null());

    // 5. /metrics reflects 1 allow + 1 deny.
    let resp = build_router(gw.clone())
        .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(
        text.contains("citadel_decisions_total{decision=\"allow\"} 1"),
        "{text}"
    );
    assert!(
        text.contains("citadel_decisions_total{decision=\"deny\"} 1"),
        "{text}"
    );
}
