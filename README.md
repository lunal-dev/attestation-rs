# Lunal Attestation

A Rust library and CLI tool for Intel TDX (Trust Domain Extensions) attestation and Intel certificate management.

## Overview

Lunal Attestation provides utilities for:
- Generating TDX attestation reports
- Fetching Intel PCS (Provisioning Certification Service) data
- Parsing and extracting Intel certificate extensions
- Compressing and encoding attestation data

## Installation

Clone the repository and build locally:

```bash
git clone https://github.com/lunal-dot-dev/attestation-rs.git
cd attestation-rs
cargo build --release
```

## Usage

### CLI Tool

The project includes a CLI tool named `attest`:

```bash
# Build with attestation features
cargo build --release --features attestation

# Run the attestation tool
./target/release/attest [options]
```

### Library Usage

Add the following to your `Cargo.toml`:

```toml
[dependencies]
lunal-attestation = { git = "https://github.com/lunal-dot-dev/attestation-rs.git" }
```

#### Basic TDX Attestation

```rust
use lunal_attestation::attestation::*;

// Get raw attestation report
let raw_report = get_raw_attestation_report()?;

// Get parsed attestation report
let parsed_report = get_parsed_attestation_report()?;

// Get compressed and base64-encoded attestation
let encoded_attestation = get_compressed_encoded_attestation()?;
```

#### PCS Client Usage

```rust
use lunal_attestation::pcs_client::PcsClient;

let client = PcsClient::new();

// Fetch QE identity
let qe_identity = client.get_qe_identity().await?;

// Fetch TCB information
let tcb_info = client.get_tcb_info("00806F050000").await?;

// Fetch PCK CRL
let pck_crl = client.get_pck_crl("platform", "der").await?;
```

#### SGX Extensions Parsing

```rust
use lunal_attestation::utils::*;

// Extract SGX extensions from a quote
let extensions = extract_sgx_extensions_from_quote(&quote);

// Parse key values from extensions
let key_values = parse_sgx_key_values(&extensions);
```


## Features

### Optional Features
- `attestation`: Enables TDX attestation capabilities (requires TDX-enabled hardware)

To enable attestation features:
```bash
cargo build --features attestation
```

## Testing

Run tests with:
```bash
# Run all tests
cargo test

# Run with attestation features
cargo test --features attestation
```

## Root Certificates

The `data/` directory contains Intel SGX root certificates required for certificate chain validation:
- `Intel_SGX_Provisioning_Certification_RootCA.cer`
- `IntelSGXRootCA.der`

## API Endpoints

The PCS client connects to Intel's Trusted Services API:
- Base URL: `https://api.trustedservices.intel.com`
- Supports both TDX and SGX certification endpoints

## Error Handling

All public functions return `Result` types with appropriate error handling for:
- Network connectivity issues
- TDX hardware unavailability
- Certificate parsing errors
- Data compression/encoding failures

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

MIT License
