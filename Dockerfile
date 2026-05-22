FROM rust:1.94-bookworm AS builder

RUN apt-get update && apt-get install -y libtss2-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo build --release -p attestation-api --bin attestation-api

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends libtss2-esys-3.0.2-0 libtss2-tctildr0 ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/attestation-api /attestation-api

EXPOSE 8400

ENTRYPOINT ["/attestation-api"]
