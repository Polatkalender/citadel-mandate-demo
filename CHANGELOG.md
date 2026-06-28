# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project aims to follow
[Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-06-28

First public release: an open, runnable demo of runtime Intent Mandate
enforcement for AI-agent payments.

### Added
- **Enforcement core** — Ed25519 mandate verification (`verify_strict`), scope
  checks (amount cap, merchant allowlist, currency, expiry), per-mandate
  **budget** (cumulative spend; replays cap out), hash-chained tamper-evident
  audit, and an action-bound, expiring token. Fail-closed on every path.
- **Token loop** — `verify_token` + `POST /v1/verify`; `/v1/authorize` returns
  the compact, verifiable token.
- **Protocol-neutral adapters** — `MandateAdapter` trait with native, AP2-style
  and ACP-style adapters mapped onto one core (`authorize_with`).
- **Surfaces** — CLI demo, HTTP gateway (`/v1/authorize`, `/v1/verify`,
  `/metrics`), TS + Python SDKs, and a **WebAssembly browser playground**
  ([live](https://polatkalender.github.io/citadel-mandate-demo/)).
- **Assurance** — 51 tests (adversarial, property-based/proptest, protocol-neutral,
  HTTP integration), a cargo-fuzz target, criterion benchmarks
  (~79 µs verify, ~124 µs full authorize), and CI across build/lint/test/Docker/
  cross-language SDKs/wasm/supply-chain (cargo-audit + cargo-deny).

### Scope (honest)
- Intent Mandates only. VC-style Ed25519 over the canonical mandate content —
  realistic AP2/ACP shapes, **not** certified W3C VC / JWS interop. The audit log
  and token are simplified illustrations of the production mechanisms.

[0.1.0]: https://github.com/Polatkalender/citadel-mandate-demo/releases/tag/v0.1.0
