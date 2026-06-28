// Print a signed Intent Mandate wire (seed-7 = the gateway's trusted "alice").
// Pipe it into the Rust verifier:
//   node sdks/ts/sign.mjs | cargo run -q --example verify_wire -- acme 12000
import { signMandate, testSeed } from "./citadel.mjs";

const mandate = {
  mandate_id: "im_ts_sdk",
  user_id: "alice@example.com",
  agent_id: "agent-x",
  intent_description: "ts sdk demo",
  max_amount_cents: 15000,
  currency: "usd",
  allowed_merchants: ["acme"],
  created_at: "2026-01-01T00:00:00Z",
  expires_at: "2030-01-01T00:00:00Z",
};

process.stdout.write(signMandate(mandate, testSeed(7)));
