//! citadel-mandate-demo CLI.
//!
//!   citadel-mandate-demo                 run the 5-scenario enforcement demo
//!   citadel-mandate-demo serve           start the HTTP gateway on :8080
//!   citadel-mandate-demo mint [variant]  print a curl-ready signed request
//!
//! mint variants: --valid (default) --tamper --expired --over --wrong

use citadel_mandate_demo::engine::{Gateway, Outcome};
use citadel_mandate_demo::mandate::{test_key, MandateKeyRegistry};
use citadel_mandate_demo::scenarios::{self, TRUSTED_USER};

const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const CYAN: &str = "\x1b[36m";
const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        None | Some("demo") => run_demo(),
        Some("serve") => citadel_mandate_demo::serve::run_blocking(),
        Some("mint") => mint(args.next().as_deref()),
        Some(other) => {
            eprintln!("unknown subcommand: {other}");
            eprintln!("usage: citadel-mandate-demo [demo | serve | mint [--tamper|--expired|--over|--wrong]]");
            std::process::exit(2);
        }
    }
}

fn run_demo() {
    let mut registry = MandateKeyRegistry::new();
    registry.trust(TRUSTED_USER, test_key(7).verifying_key());
    let mut gw = Gateway::new(registry, test_key(200));

    println!();
    println!("{BOLD}Citadel — AP2 Intent Mandate enforcement{RESET} {DIM}(open demo){RESET}");
    println!("{DIM}An AI agent can only spend within the mandate its user cryptographically signed.{RESET}");
    println!();
    println!("{BOLD}{:<34} {:<7} DETAIL{RESET}", "SCENARIO", "RESULT");
    println!("{DIM}{}{RESET}", "-".repeat(76));

    let mut all_ok = true;
    for s in scenarios::build_all(&test_key(7)) {
        let outcome = gw.authorize(&s.wire, &s.charge);
        all_ok &= outcome.is_allow() == s.expect_allow;

        let (tag, color) = match &outcome {
            Outcome::Allow { .. } => ("ALLOW", GREEN),
            Outcome::Deny { .. } => ("DENIED", RED),
        };
        let detail = match &outcome {
            Outcome::Allow {
                token_id,
                audit_seq,
                ..
            } => {
                format!("token {CYAN}{token_id}{RESET} {DIM}· audit #{audit_seq}{RESET}")
            }
            Outcome::Deny { reason, audit_seq } => {
                format!("{reason} {DIM}· audit #{audit_seq}{RESET}")
            }
        };
        println!(
            "{label:<34} {color}{tag:<7}{RESET}{detail}",
            label = s.label,
            color = color,
            tag = tag,
            detail = detail
        );
    }

    println!("{DIM}{}{RESET}", "-".repeat(76));
    let verified = gw.audit.verify();
    let head = gw.audit.head_hex();
    println!(
        "audit chain {color}{state}{RESET} {DIM}· {n} entries · head {head}…{RESET}",
        color = if verified { GREEN } else { RED },
        state = if verified { "VERIFIED" } else { "BROKEN" },
        n = gw.audit.len(),
        head = &head[..12]
    );
    println!();

    if !all_ok {
        eprintln!("a scenario did not match its expected outcome");
        std::process::exit(1);
    }
}

fn mint(variant: Option<&str>) {
    let idx = match variant {
        None | Some("--valid") => 0,
        Some("--tamper") => 1,
        Some("--expired") => 2,
        Some("--over") => 3,
        Some("--wrong") => 4,
        Some(x) => {
            eprintln!("unknown mint variant: {x} (use --valid|--tamper|--expired|--over|--wrong)");
            std::process::exit(2);
        }
    };
    let s = scenarios::build_all(&test_key(7))
        .into_iter()
        .nth(idx)
        .expect("scenario exists");
    let mandate: serde_json::Value =
        serde_json::from_slice(&s.wire).expect("scenario wire is valid json");
    let body = serde_json::json!({
        "mandate": mandate,
        "charge": {
            "merchant": s.charge.merchant,
            "amount_cents": s.charge.amount_cents,
            "currency": s.charge.currency,
        }
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&body).expect("body json")
    );
}
