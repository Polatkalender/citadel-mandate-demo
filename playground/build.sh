#!/usr/bin/env bash
# Build the WebAssembly playground (the real Rust core, compiled to wasm).
#   1. install wasm-pack:  https://rustwasm.github.io/wasm-pack/installer/
#   2. ./playground/build.sh
#   3. serve it (wasm needs http, not file://):
#        (cd playground && python -m http.server)  ->  http://localhost:8000
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v wasm-pack >/dev/null; then
  echo "wasm-pack not found. Install: curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh"
  exit 1
fi

wasm-pack build --target web --out-dir playground/pkg --no-typescript --release
echo "✓ built playground/pkg — now: (cd playground && python -m http.server) and open http://localhost:8000"
