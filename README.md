# Attestation

A Rust library providing a unified interface for TEE (Trusted Execution Environment) attestation evidence generation and verification.

## Supported Platforms

| Platform                 | Attest | Verify | WASM Verify |
| ------------------------ | ------ | ------ | ----------- |
| AMD SEV-SNP (bare-metal) | Yes    | Yes    | Yes         |
| Intel TDX (bare-metal)   | Yes    | Yes    | Yes         |
| Azure SEV-SNP (vTPM)     | Yes    | Yes    | Yes         |
| Azure TDX (vTPM)         | Yes    | Yes    | Yes         |

## Feature Flags

```toml
[dependencies]
attestation = { path = ".", features = ["snp", "tdx"] }
```

| Feature  | Description                                                               |
| -------- | ------------------------------------------------------------------------- |
| `snp`    | AMD SEV-SNP support (verify always, attest when `attest` also enabled)    |
| `tdx`    | Intel TDX support                                                         |
| `az-snp` | Azure SEV-SNP vTPM support (implies `snp`)                                |
| `az-tdx` | Azure TDX vTPM support (implies `tdx`)                                    |
| `attest` | Enable guest-side evidence generation (Linux-only, requires TEE hardware) |
| `cli`    | Build the `attestation-cli` binary                                        |

All four platform features are enabled by default. Verification is always compiled when a platform feature is enabled. The `attest` feature gates all guest-side code that requires hardware access.

## Usage

### Verifier (Server-Side or WASM)

```rust
use attestation::{VerifyParams, VerificationResult};

#[tokio::main]
async fn main() {
    // evidence_json is a self-describing AttestationEvidence envelope
    let evidence_json: &[u8] = b"...";

    let params = VerifyParams {
        expected_report_data: Some(vec![0xAA; 64]),
        ..Default::default()
    };

    let result = attestation::verify(evidence_json, &params).await.unwrap();

    println!("Signature valid: {}", result.signature_valid);
    println!("Platform: {}", result.platform);
    println!("Launch digest: {}", result.claims.launch_digest);
    println!("Report data match: {:?}", result.report_data_match);
}
```

### Verifier with Custom Providers

```rust
use attestation::{Verifier, VerifyParams};

#[tokio::main]
async fn main() {
    let verifier = Verifier::new();
    // Or with custom cert/collateral providers:
    // let verifier = Verifier::new()
    //     .with_cert_provider(my_cert_provider)
    //     .with_tdx_provider(my_tdx_provider);

    let result = verifier
        .verify(evidence_json, &VerifyParams::default())
        .await
        .unwrap();
}
```

### Attester (Guest-Side Agent)

```rust
#[tokio::main]
async fn main() {
    // Auto-detect the TEE platform
    let platform = attestation::detect().expect("no TEE platform detected");
    println!("Detected platform: {}", platform);

    // Generate evidence with a challenge nonce
    let nonce = b"server-provided-challenge-nonce";
    let evidence_json = attestation::attest(platform, nonce).await.unwrap();

    // Send evidence_json to the verifier — it's a self-describing envelope
    println!("Evidence: {} bytes", evidence_json.len());
}
```

## Examples

Each platform has a dedicated example. Run on the appropriate hardware:

```bash
cargo run --example snp    --features "snp,attest"
cargo run --example tdx    --features "tdx,attest"
cargo run --example az_snp --features "az-snp,attest"
cargo run --example az_tdx --features "az-tdx,attest"
```

Azure examples accept an optional nonce argument:

```bash
cargo run --example az_snp --features "az-snp,attest" -- "my-custom-nonce"
```

## CLI

A CLI binary is available for attestation and verification from the command line:

```bash
# Build the CLI
cargo build --release --features cli

# Generate evidence (on TEE hardware, Linux only)
cargo build --release --features "cli,attest"
./target/release/attestation-cli attest --report-data "my-nonce"

# Verify evidence (works anywhere)
echo "$EVIDENCE" | ./target/release/attestation-cli verify
```

## Evidence JSON Schemas

### SNP Evidence

```json
{
  "attestation_report": "<base64-encoded 1184-byte SNP report>",
  "cert_chain": {
    "vcek": "<base64-encoded DER certificate>",
    "ask": "<base64-encoded DER certificate, optional>",
    "ark": "<base64-encoded DER certificate, optional>"
  }
}
```

### TDX Evidence

```json
{
  "quote": "<base64-encoded TDX quote bytes>",
  "cc_eventlog": "<base64-encoded CCEL eventlog, optional>"
}
```

### Azure SNP Evidence

```json
{
  "version": 1,
  "tpm_quote": {
    "signature": "<hex-encoded RSA signature>",
    "message": "<hex-encoded TPMS_ATTEST>",
    "pcrs": ["<hex-encoded 32-byte PCR value>", "...(24 entries)"]
  },
  "hcl_report": "<url-safe-base64-encoded HCL report (2600 bytes)>",
  "vcek": "<url-safe-base64-encoded DER certificate>"
}
```

### Azure TDX Evidence

```json
{
  "version": 1,
  "tpm_quote": {
    "signature": "<hex-encoded RSA signature>",
    "message": "<hex-encoded TPMS_ATTEST>",
    "pcrs": ["<hex-encoded 32-byte PCR value>", "...(24 entries)"]
  },
  "hcl_report": "<url-safe-base64-encoded HCL report (2600 bytes)>",
  "td_quote": "<url-safe-base64-encoded TD quote>"
}
```

### Verification Result

```json
{
  "signature_valid": true,
  "platform": "snp",
  "claims": {
    "launch_digest": "<96-char hex string (48 bytes)>",
    "report_data": "<128-char hex string (64 bytes)>",
    "signed_data": "<hex-encoded bytes>",
    "init_data": "<hex-encoded bytes>",
    "tcb": {
      "type": "Snp",
      "bootloader": 3,
      "tee": 0,
      "snp": 8,
      "microcode": 115
    },
    "platform_data": {
      "policy": { "abi_major": 0, "debug_allowed": false, "..." : "..." },
      "vmpl": 0,
      "chip_id": "<128-char hex>"
    }
  },
  "report_data_match": true,
  "init_data_match": null
}
```

## Running Tests

```bash
# Unit tests (no hardware needed)
cargo test --features snp
cargo test --features tdx
cargo test --features az-snp
cargo test --features az-tdx

# Integration tests on Azure SNP CVM
cargo test --test az_snp_live --features "az-snp,attest" -- --ignored

# Integration tests on Azure TDX CVM
cargo test --test az_tdx_live --features "az-tdx,attest" -- --ignored

# Benchmarks
cargo bench --features snp
cargo bench --features tdx
cargo bench --features az-snp
cargo bench --features az-tdx
```

## WASM Support

The library compiles to `wasm32-unknown-unknown` for verifier-only use:

```bash
cargo check --target wasm32-unknown-unknown --no-default-features --features snp,tdx,az-snp,az-tdx
```

The `attest` feature is automatically excluded on WASM. All verification uses pure-Rust crypto (no OpenSSL dependency).

## Bundled Certificates

AMD root certificates (ARK + ASK) for Milan, Genoa, and Turin processors are embedded at compile time. Per-chip VCEK certificates are fetched on demand from AMD KDS or Azure IMDS.

## License

Apache-2.0
