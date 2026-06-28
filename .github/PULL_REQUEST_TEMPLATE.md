<!-- Thanks for contributing! Keep it small and fail-closed. -->

## What & why

<!-- One or two sentences. Link an issue if there is one. -->

## Checklist

- [ ] `cargo fmt --all` and `cargo clippy --all-targets -- -D warnings` are clean
- [ ] `cargo test` passes
- [ ] If I touched the mandate shape or a signer: the signed canonical bytes still
      match across Rust and the SDKs (see `sdks/README.md`), with a tamper test
- [ ] Behaviour stays **fail-closed** (no path turns a deny into an allow)
