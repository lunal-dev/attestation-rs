# Attestation Workspace

[![CI](https://github.com/lunal-dot-dev/attestation-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/lunal-dot-dev/attestation-rs/actions/workflows/ci.yml)

Rust workspace for TEE attestation libraries, tools, and services.

## Workspace Members

| Package | Path | Description |
| --- | --- | --- |
| `attestation` | `crates/attestation` | Core TEE attestation evidence generation and verification library |
| `attestation-cli` | `crates/attestation-cli` | CLI for generating and verifying attestation evidence |
| `attestation-api` | `crates/attestation-api` | REST API service wrapping the attestation library |
| `attestation-wasm` | `crates/attestation-wasm` | WASM verification harness |

## Common Commands

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Build the CLI with guest-side attestation support:

```bash
cargo build -p attestation-cli --release --features attest
```

Build the REST service:

```bash
cargo build -p attestation-api --release
docker build .
```

The service image is published as `ghcr.io/lunal-dev/attestation-api`.

## Documentation

- Core library: `crates/attestation/README.md`
- REST service: `crates/attestation-api/README.md`
