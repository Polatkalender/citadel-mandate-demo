# Contributing

Thanks for looking! This is a small, focused open demo of **runtime Intent Mandate
enforcement** for AI-agent payments. Contributions that keep it small, clear and
fail-closed are very welcome.

## Build & test

```bash
cargo run            # the 5-scenario demo
cargo test           # 49 tests (adversarial, properties, protocol-neutral, enforcement)
cargo clippy --all-targets -- -D warnings
cargo fmt --all
cargo bench          # criterion benchmarks
bash sdks/check.sh   # cross-language SDK check (needs node + python+cryptography)
./playground/build.sh   # build the WASM playground (needs wasm-pack)
```

CI runs `fmt`, `clippy -D warnings`, `test`, the demo, the Docker build, the
cross-language SDK check, and the WASM build on every push. All must pass.

## Where things live

| Area | File |
|---|---|
| Verification core (Ed25519) | `src/mandate.rs` |
| Scope / limit checks | `src/scope.rs` |
| Pipeline (verify → scope → budget → token → audit) | `src/engine.rs` |
| Protocol adapters (native, AP2, ACP) | `src/protocol.rs` |
| Audit chain · DPoP-style token | `src/audit.rs` · `src/token.rs` |
| HTTP gateway | `src/serve.rs` |
| WASM bindings · playground | `src/wasm.rs` · `playground/` |
| SDKs (TS, Python) | `sdks/` |

## The one rule that matters: the canonical contract

A mandate signature covers a **canonical** byte string. Any signer (Rust, the
SDKs, a new protocol adapter) must produce exactly these bytes or verification
fails — see [`sdks/README.md`](sdks/README.md). If you add a field to a mandate,
make sure it is inside the signed payload, and add a tamper test for it.

## Good first issues

- Add an **x402-style adapter** in `src/protocol.rs` (mirror `Ap2`/`Acp`).
- Add a **`Justfile`** for the common commands above.
- Playground: add a **"wrong key"** toggle to show an untrusted-signer deny.
- Add an SDK in **another language** (Go, Java…) that passes `sdks/check.sh`.

Open an issue first for anything larger. Every change should keep `cargo test`
green and stay fail-closed.

## License

By contributing you agree your contribution is licensed under [Apache-2.0](LICENSE).
