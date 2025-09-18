
# Lunal-Attestation

A comprehensive Rust library and CLI toolkit for confidential computing attestation, supporting Intel TDX, AMD SEV-SNP, and WebAssembly-based verification across multiple platforms.

## Overview

`lunal-attestation` provides a unified interface for generating, processing, and verifying cryptographic attestations in confidential computing environments. The library supports multiple Trusted Execution Environment (TEE) platforms and offers native, CLI, and WebAssembly deployment options.

## Features

The library supports different compilation modes through feature flags:

### Feature Flags

- **`default`**: Basic library functionality without TEE-specific features
- **`attestation-tdx`**: Intel TDX attestation support (requires `tdx` dependency)
- **`attestation`**: AMD SEV-SNP attestation support via `amd-vtpm`
- **`wasm`**: WebAssembly support for browser-based verification

### Platform Support

- **Intel TDX**: Quote generation, compression, and DCAP v4 verification
- **AMD SEV-SNP**: vTPM-based attestation with HCL report integration
- **SGX Extensions**: Certificate parsing and collateral fetching
- **Web Browsers**: WASM-compiled verification capabilities

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
lunal-attestation = { git = "https://github.com/lunal-dev/attestation-rs.git" }

# For TDX attestation
lunal-attestation = { git = "...", features = ["attestation-tdx"] }

# For AMD attestation
lunal-attestation = { git = "...", features = ["attestation"] }

# For WebAssembly
lunal-attestation = { git = "...", features = ["wasm"] }
```

## Usage

### Intel TDX Attestation

```rust
use lunal_attestation::attestation::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate raw TDX attestation report
    let raw_report = get_raw_attestation_report()?;
    println!("Raw report: {} bytes", raw_report.len());

    // Get parsed QuoteV4 structure
    let parsed_report = get_parsed_attestation_report()?;
    println!("Quote version: {}", parsed_report.header.version);

    // Get compressed and encoded attestation
    let encoded = get_compressed_encoded_attestation()?;
    println!("Encoded attestation: {}", encoded);

    Ok(())
}
```

### AMD SEV-SNP Attestation

```rust
use lunal_attestation::amd::attest;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let custom_data = b"my-application-nonce";

    // Generate compressed attestation evidence
    let evidence = attest::attest_compressed(custom_data).await?;
    println!("Evidence: {}", evidence);

    // Save to file
    std::fs::write("evidence.b64", &evidence)?;

    Ok(())
}
```

### Quote Verification

```rust
use lunal_attestation::verify::{verify_attestation, fetch_collaterals};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let attestation_data = std::fs::read_to_string("attestation.b64")?;

    match verify_attestation(&attestation_data).await {
        Ok(result) => {
            println!("✅ Verification successful!");
            println!("Quote status: {:?}", result.quote_status);
            println!("Collateral expiry: {:?}", result.collateral_expiration_status);
        }
        Err(e) => println!("❌ Verification failed: {}", e),
    }

    Ok(())
}
```

### Intel PCS Integration

```rust
use lunal_attestation::pcs_client::PcsClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = PcsClient::new();

    // Fetch TCB information
    let tcb_response = client.get_tcb_info("00806F050000").await?;
    println!("TCB Info: {}", serde_json::to_string_pretty(&tcb_response.json_data)?);

    // Get certificate chain
    println!("Certificate chain has {} certs", tcb_response.issuer_chain_certs.len());

    // Fetch QE identity
    let qe_identity = client.get_qe_identity().await?;
    println!("QE Identity: {}", serde_json::to_string_pretty(&qe_identity)?);

    Ok(())
}
```

### AMD Evidence Verification

```rust
use lunal_attestation::amd::verify::verify_compressed;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let custom_data = b"expected-nonce";
    let evidence = std::fs::read_to_string("evidence.b64")?;

    // Verify with custom data validation enabled
    match verify_compressed(custom_data, evidence.trim(), Some(true)).await {
        Ok(result) => {
            println!("✅ AMD attestation verified!");
            println!("Report data: {}", result.report_data);
        }
        Err(e) => println!("❌ AMD verification failed: {}", e),
    }

    Ok(())
}
```

### WebAssembly Usage

Build for web deployment:

```bash
# Build WASM package
make wasm

# Development build
make wasm-dev
```

Use in web applications:

```javascript
import init, { verify_attestation_wasm } from './pkg/lunal_attestation.js';

async function verifyInBrowser(attestationData) {
    await init();

    try {
        const result = verify_attestation_wasm(attestationData);
        console.log('Verification successful:', result);
    } catch (error) {
        console.error('Verification failed:', error);
    }
}
```

## CLI Tools

The library provides specialized CLI binaries:

### TDX Attestation Tool

```bash
# Build TDX binary
make build-tdx

# Generate raw attestation
./target/release/attest-tdx --format raw

# Generate compressed attestation
./target/release/attest-tdx --format compressed
```

### AMD Attestation Tool

```bash
# Build AMD binary
make build-amd

# Generate attestation with custom data
./target/release/attest-amd attest "my-nonce-data"

# Verify evidence from file
./target/release/attest-amd verify evidence.b64 "my-nonce-data" --check-custom-data
```

## Build

The project includes a comprehensive Makefile:

```bash
# Build all binaries
make build

# Build specific platforms
make build-tdx     # TDX only
make build-amd     # AMD only

# WebAssembly builds
make wasm          # Production WASM
make wasm-dev      # Development WASM

# System installation
make install       # Install to /usr/local/bin
```

## License

Licensed under the MIT License. See LICENSE for details.

## Contributing

Contributions welcome! Please ensure:

- Tests pass: `cargo test --all-features`
- WASM builds: `make wasm`
- Code formatting: `cargo fmt`
- Linting: `cargo clippy`