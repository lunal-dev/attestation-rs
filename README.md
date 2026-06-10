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

## WASM verification in the browser

`attestation-wasm` compiles the SNP verification path to WebAssembly so evidence
can be verified entirely client-side. To produce a blob usable in a browser, build
with the `web` target (this requires [`wasm-pack`](https://rustwasm.github.io/wasm-pack/installer/)):

```bash
cd crates/attestation-wasm
wasm-pack build --target web --release
```

This writes an ES module and the `.wasm` binary to `pkg/`:

- `pkg/attestation_wasm.js` — JS bindings and the `init` loader
- `pkg/attestation_wasm_bg.wasm` — the WASM blob

Serve `pkg/` over HTTP (browsers won't load WASM from `file://`) and use it from a
module script:

```html
<script type="module">
  import init, { verify_snp } from './pkg/attestation_wasm.js';

  await init(); // fetches and instantiates the .wasm blob

  // evidence: SNP evidence JSON with an inline cert_chain.vcek (base64 DER)
  // generation: "milan" | "genoa" | "turin"
  // expectedReportData (optional): Uint8Array of the nonce to bind against
  const resultJson = verify_snp(
    JSON.stringify(evidence),
    'genoa',
    new TextEncoder().encode('my-nonce'),
  );
  console.log(JSON.parse(resultJson));
</script>
```

For a Node.js end-to-end example (generate live evidence, fetch the VCEK from AMD
KDS, verify in WASM), build with `--target nodejs` and run
`crates/attestation-wasm/example.mjs`.

## Documentation

- Core library: `crates/attestation/README.md`
- REST service: `crates/attestation-api/README.md`
