# attestation

A Rust library providing a unified interface for TEE (Trusted Execution Environment) attestation evidence generation and verification.

## Supported Platforms

| Platform | Attest | Verify | WASM Verify |
|----------|--------|--------|-------------|
| AMD SEV-SNP (bare-metal) | Yes | Yes | Yes |
| Intel TDX (bare-metal) | Yes | Yes | Yes |
| Azure SEV-SNP (vTPM) | Yes | Yes | Yes |
| Azure TDX (vTPM) | Stub | Yes | Yes |

## Feature Flags

```toml
[dependencies]
attestation = { path = ".", features = ["snp", "tdx"] }
```

| Feature | Description |
|---------|-------------|
| `snp` | AMD SEV-SNP support (verify always, attest when `attest` also enabled) |
| `tdx` | Intel TDX support |
| `az-snp` | Azure SEV-SNP vTPM support (implies `snp`) |
| `az-tdx` | Azure TDX vTPM support (implies `tdx`) |
| `all-platforms` | Enable all platform features |
| `attest` | Enable guest-side evidence generation (Linux-only, requires TEE hardware) |

Verification is always compiled when a platform feature is enabled. The `attest` feature gates all guest-side code that requires hardware access.

## Usage

### Verifier (Server-Side or WASM)

```rust
use attestation::platforms::snp::Snp;
use attestation::platforms::Platform;
use attestation::types::VerifyParams;

#[tokio::main]
async fn main() {
    // Deserialize evidence received from the TEE guest
    let evidence_json = r#"{"attestation_report":"...","cert_chain":null}"#;
    let evidence: attestation::platforms::snp::evidence::SnpEvidence =
        serde_json::from_str(evidence_json).unwrap();

    // Set up verification parameters
    let params = VerifyParams {
        expected_report_data: Some(vec![0xAA; 64]),  // expected nonce
        expected_init_data_hash: None,
    };

    // Verify
    let snp = Snp::with_default_provider();
    let result = snp.verify(&evidence, &params).await.unwrap();

    println!("Signature valid: {}", result.signature_valid);
    println!("Platform: {}", result.platform);
    println!("Launch digest: {}", result.claims.launch_digest);
    println!("Report data match: {:?}", result.report_data_match);
}
```

### Attester (Guest-Side Agent)

```rust
use attestation::platforms::Platform;

#[tokio::main]
async fn main() {
    // Auto-detect the TEE platform
    let platform = attestation::detect().expect("no TEE platform detected");
    println!("Detected platform: {}", platform.platform_type());

    // Generate evidence with a challenge nonce
    let nonce = b"server-provided-challenge-nonce";
    let evidence_json = platform.attest_json(nonce).await.unwrap();

    // Send evidence_json to the verifier
    println!("Evidence: {}", evidence_json);
}
```

### Azure SNP CVM (Full Roundtrip)

```rust
use attestation::platforms::az_snp::AzSnp;
use attestation::platforms::Platform;
use attestation::types::VerifyParams;

#[tokio::main]
async fn main() {
    let az_snp = AzSnp::with_default_provider();

    // Generate evidence (requires tpm2-tools on Azure CVM)
    let evidence = az_snp.attest(b"my-nonce").await.unwrap();

    // Verify the evidence
    let params = VerifyParams::default();
    let result = az_snp.verify(&evidence, &params).await.unwrap();

    assert!(result.signature_valid);
    println!("Claims: {}", serde_json::to_string_pretty(&result.claims).unwrap());
}
```

## Architecture

```
attestation/
├── src/
│   ├── lib.rs           # Public API: detect(), re-exports
│   ├── error.rs         # AttestationError enum
│   ├── types.rs         # PlatformType, VerifyParams, VerificationResult, Claims, TcbInfo
│   ├── collateral.rs    # CertProvider trait + DefaultCertProvider (HTTP + cache)
│   ├── utils.rs         # SHA-256/384, padding, constant-time comparison
│   └── platforms/
│       ├── mod.rs       # Platform trait
│       ├── snp/         # AMD SEV-SNP: report parsing, ECDSA P-384 sig, cert chain
│       ├── tdx/         # Intel TDX: quote parsing (v4/v5), ECDSA P-256 sig
│       ├── az_snp/      # Azure SNP: TPM sig, HCL report, var_data binding
│       ├── az_tdx/      # Azure TDX: TPM sig, HCL report, TDX DCAP
│       └── tpm_common.rs # Shared TPM/HCL: quote decode, PCR verify, JWK AK extraction
├── benches/
│   └── verification.rs  # 18 criterion benchmarks
├── tests/
│   └── az_snp_live.rs   # Live Azure SNP CVM integration tests
└── test_data/           # Fixtures from CoCo trustee repo
```

## Verification Pipeline

### SNP (Bare-Metal)
1. Parse 1184-byte attestation report
2. Determine processor generation (Milan/Genoa/Turin) from CPUID
3. Validate cert chain: ARK (bundled) -> ASK -> VCEK/VLEK (RSA-PSS SHA-384)
4. Verify report ECDSA P-384 signature against VCEK public key
5. Check VMPL == 0, report_data binding, host_data binding
6. Extract claims (measurement, TCB, policy flags, chip_id)

### TDX (Bare-Metal)
1. Parse TDX quote (v4: 48B header + 584B body, or v5 format)
2. Verify ECDSA P-256 signature (DCAP)
3. Check report_data binding, MRCONFIGID binding
4. Extract claims (MRTD, RTMRs, MRSEAM, TCB SVN, attributes)

### Azure SNP (vTPM)
1. Parse HCL report -> extract SNP report + JWK var_data
2. Verify TPM RSA signature (AK from JWK JSON)
3. Verify TPM nonce and PCR digest integrity
4. Validate HCL binding: SHA-256(var_data) == report_data[0:32]
5. Verify SNP report signature + cert chain
6. Check PCR[8] for init_data binding
7. Extract SNP claims + TPM PCR values

### Azure TDX (vTPM)
1. Parse HCL report -> extract TDX report + JWK var_data
2. Verify TPM RSA signature + nonce + PCR integrity
3. Parse and verify TDX DCAP quote
4. Validate HCL binding: SHA-256(var_data) == td_quote.report_data[0:32]
5. Extract TDX claims + TPM PCR values

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
  "platform": "Snp",
  "claims": {
    "launch_digest": "<96-char hex string (48 bytes)>",
    "report_data": "<128-char hex string (64 bytes)>",
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
cargo test --features all-platforms

# Integration tests on Azure SNP CVM (requires tpm2-tools + TPM access)
cargo test --test az_snp_live --features "all-platforms,attest" -- --ignored

# Benchmarks
cargo bench --features all-platforms
```

## WASM Support

The library compiles to `wasm32-unknown-unknown` for verifier-only use:

```bash
cargo check --target wasm32-unknown-unknown --features all-platforms
```

The `attest` feature is automatically excluded on WASM. All verification uses pure-Rust crypto (no OpenSSL dependency).

## Bundled Certificates

AMD root certificates (ARK + ASK) for Milan, Genoa, and Turin processors are embedded at compile time. Per-chip VCEK certificates are fetched on demand from AMD KDS or Azure IMDS.

## License

Apache-2.0
