# ── build ──────────────────────────────────────────────────────────
FROM rust:1-slim AS build
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
RUN cargo build --release

# ── runtime ────────────────────────────────────────────────────────
FROM debian:bookworm-slim
COPY --from=build /app/target/release/citadel-mandate-demo /usr/local/bin/citadel-mandate-demo
# Default: run the 5-scenario demo. Override with a subcommand, e.g.:
#   docker run --rm -p 8080:8080 citadel-mandate-demo serve
ENTRYPOINT ["citadel-mandate-demo"]
