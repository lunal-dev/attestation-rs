# Lunal Attestation

A Rust library and CLI tools for confidential computing attestation, supporting Intel TDX (Trust Domain Extensions) and AMD SEV-SNP (Secure Encrypted Virtualization - Secure Nested Paging).

## Overview

Lunal Attestation provides utilities for:
- Generating and verifying TDX attestation reports
- Generating and verifying AMD SEV-SNP attestation reports
- Fetching Intel PCS (Provisioning Certification Service) data
- Parsing and extracting Intel certificate extensions
- Compressing and encoding attestation data

## Installation

Clone the repository and build locally:

```bash
git clone https://github.com/lunal-dot-dev/attestation-rs.git
cd attestation-rs
```

## Usage


### CLI Tools

The project includes separate CLI tools for different attestation types:

#### TDX Attestation
```bash
# Build TDX attestation tool
cargo build --release --bin attest-tdx --features attestation

# Run TDX attestation tool
./target/release/attest-tdx [options]
```

#### SEV-SNP Attestation
```bash
# Build SEV-SNP attestation tool
cargo build --release --bin attest-sev-snp --features attestation

# Run SEV-SNP attestation tool
./target/release/attest-sev-snp [options]
```

#### Build Both Tools
```bash
# Build both attestation tools
cargo build --release --features attestation
```

### Library Usage

Add the following to your `Cargo.toml`:

```toml
[dependencies]
# For TDX support
lunal-attestation = { git = "https://github.com/lunal-dot-dev/attestation-rs.git", features = ["tdx"] }

# For SEV-SNP support
lunal-attestation = { git = "https://github.com/lunal-dot-dev/attestation-rs.git", features = ["sev-snp"] }

# For both
lunal-attestation = { git = "https://github.com/lunal-dot-dev/attestation-rs.git", features = ["tdx", "sev-snp"] }
```

#### Basic TDX Attestation

```rust
use lunal_attestation::tdx::attestation::*;

// Get raw attestation report
let raw_report = get_raw_attestation_report()?;

// Get parsed attestation report
let parsed_report = get_parsed_attestation_report()?;

// Get compressed and base64-encoded attestation
let encoded_attestation = get_compressed_encoded_attestation()?;
```

#### TDX Attestation Verification

```rust
use lunal_attestation::tdx::verify::*;

// Verify TDX attestation
let result = verify_attestation(&attestation_data).await?;
println!("Verification result: {:?}", result);
```

#### SEV-SNP Attestation Verification

```rust
use lunal_attestation::sev_snp::verify::*;

// Verify SEV-SNP attestation
let result = verify_attestation(&attestation_data).await?;
println!("Verification result: {:?}", result);
```


## Features

### Optional Features
- `tdx`: Enables TDX attestation capabilities (requires TDX-enabled hardware)
- `sev-snp`: Enables AMD SEV-SNP attestation capabilities (requires SEV-SNP-enabled hardware)

To build with specific features:
```bash
# TDX only
cargo build --features tdx

# SEV-SNP only
cargo build --features sev-snp

```


## API Endpoints

The TDX PCS client connects to Intel's Trusted Services API:
- Base URL: `https://api.trustedservices.intel.com`
- Supports both TDX and SGX certification endpoints


## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

MIT License