// Citadel mandate SDK (TypeScript/Node, zero-dependency — uses built-in crypto).
//
// Signs an Intent Mandate so the Citadel gateway will accept it. The canonical
// bytes MUST match what the Rust verifier reconstructs:
//   * field order = the struct order below (do not reorder),
//   * compact JSON (no whitespace),
//   * RFC3339 UTC timestamps with 'Z', whole seconds,
//   * detached Ed25519 signature over sha256(canonical).
//
// Verify it end-to-end:  node sdks/ts/sign.mjs | cargo run -q --example verify_wire -- acme 12000

import crypto from "node:crypto";

// Build the canonical mandate bytes (the thing that gets signed). Field order is
// load-bearing — it must equal the Rust IntentMandate struct field order.
export function canonicalMandate(m) {
  const ordered = {
    mandate_id: m.mandate_id,
    user_id: m.user_id,
    agent_id: m.agent_id,
    intent_description: m.intent_description,
    max_amount_cents: m.max_amount_cents,
    currency: m.currency,
    allowed_merchants: m.allowed_merchants,
    created_at: m.created_at,
    expires_at: m.expires_at,
  };
  return Buffer.from(JSON.stringify(ordered), "utf8"); // compact, insertion order
}

// Ed25519 private key from a raw 32-byte seed (wraps it in PKCS#8 DER).
export function ed25519FromSeed(seed) {
  const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
  const der = Buffer.concat([PKCS8_PREFIX, Buffer.from(seed)]);
  return crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

// Sign a mandate and return the wire JSON string (mandate fields + signature_b64).
export function signMandate(mandate, seed) {
  const canonical = canonicalMandate(mandate);
  const digest = crypto.createHash("sha256").update(canonical).digest();
  const key = ed25519FromSeed(seed);
  const sig = crypto.sign(null, digest, key); // Ed25519 over the 32-byte digest
  return JSON.stringify({ ...mandate, signature_b64: sig.toString("base64") });
}

// A deterministic 32-byte test seed (TEST ONLY — obviously not a real secret).
export function testSeed(byte) {
  return Buffer.alloc(32, byte);
}
