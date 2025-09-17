# vtpm-attestation

A Rust library for vTPM-based attestation in confidential computing environments, supporting both AMD SEV-SNP and Intel TDX platforms through Host Compatibility Layer (HCL) integration.

## Overview

`vtpm-attestation` provides a comprehensive toolkit for working with virtual Trusted Platform Modules (vTPMs) in confidential virtual machines. The library enables generation and verification of cryptographic attestations that prove the integrity and authenticity of confidential workloads.

Key capabilities:
- **vTPM Operations**: Generate quotes, extend PCRs, manage attestation keys
- **HCL Report Parsing**: Process attestation reports from multiple TEE architectures
- **Cryptographic Verification**: Validate quote signatures and attestation chains
- **Multi-Platform Support**: AMD SEV-SNP and Intel TDX compatibility

## Architecture

```
┌─────────────────┐    ┌─────────────────┐
│   Application   │    │    Verifier     │
└─────────────────┘    └─────────────────┘
         │                       │
         ▼                       ▼
┌─────────────────┐    ┌─────────────────┐
│  vTPM Module    │    │ Verify Module   │
│  - Quotes       │    │ - Signatures    │
│  - PCR Extend   │    │ - Nonces        │
│  - AK Management│    │ - PCR Digests   │
└─────────────────┘    └─────────────────┘
         │                       │
         └───────────┬───────────┘
                     ▼
         ┌─────────────────┐
         │   HCL Module    │
         │ - SNP Reports   │
         │ - TDX Reports   │
         │ - AK Extraction │
         └─────────────────┘
                     │
                     ▼
         ┌─────────────────┐
         │ Hardware TEE    │
         │ (SNP/TDX)       │
         └─────────────────┘
```

## Features

The library supports different compilation modes through feature flags:

### Feature Flags

- **`default`**: Includes verifier functionality
- **`attester`**: Enables TPM operations and quote generation (requires `tpm` + `openssl`)
- **`verifier`**: Enables quote verification (uses `sev/crypto_nossl`)
- **`tpm`**: Core TPM operations via `tss-esapi`

### Platform Support

- **AMD SEV-SNP**: Full support for SNP attestation reports and VCEK validation
- **Intel TDX**: TDX report parsing (implementation in progress)
- **vTPM**: Hardware-agnostic TPM 2.0 operations

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
vtpm-attestation = "0.7.3"

# For attestation generation
vtpm-attestation = { git = "https://github.com/lunal-dev/lunal-attestation.git" }

# For verification only
vtpm-attestation = { git = "https://github.com/lunal-dev/lunal-attestation.git" }
```

### System Dependencies

**For attester mode:**
- TPM 2.0 hardware or simulator
- `tpm2-tss` library
- OpenSSL development headers

**Ubuntu/Debian:**
```bash
sudo apt-get install libtss2-dev libssl-dev
```

**RHEL/CentOS:**
```bash
sudo yum install tpm2-tss-devel openssl-devel
```

## Usage

### Generating vTPM Quotes

```rust
use vtpm_attestation::{vtpm, quote::Quote};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a quote with custom nonce
    let nonce = b"challenge_data";
    let quote = vtpm::get_quote(nonce)?;

    // Access quote components
    println!("Quote signature: {:02x?}", quote.signature);
    println!("PCR values: {:?}", quote.pcrs_sha256().collect::<Vec<_>>());

    // Serialize to JSON
    let json = quote.to_json_pretty()?;
    println!("Quote JSON: {}", json);

    Ok(())
}
```

### Verifying Quotes

```rust
use vtpm_attestation::{quote::Quote, vtpm::VerifyError};
use openssl::pkey::PKey;

fn verify_quote(quote_json: &str, ak_pub_pem: &[u8], expected_nonce: &[u8])
    -> Result<(), Box<dyn std::error::Error>> {

    // Parse quote and public key
    let quote = Quote::from_json(quote_json)?;
    let public_key = PKey::public_key_from_pem(ak_pub_pem)?;

    // Verify signature and nonce
    quote.verify(&public_key, expected_nonce)?;

    println!("Quote verification successful!");
    Ok(())
}
```

### Processing HCL Reports

```rust
use vtpm_attestation::hcl::{HclReport, ReportType};
use sev::firmware::guest::AttestationReport;

fn process_hcl_report(report_bytes: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
    let hcl_report = HclReport::new(report_bytes)?;

    match hcl_report.report_type() {
        ReportType::Snp => {
            // Extract SNP report
            let snp_report: AttestationReport = (&hcl_report).try_into()?;
            println!("SNP Report version: {}", snp_report.version);
        },
        ReportType::Tdx => {
            println!("TDX report detected");
        }
    }

    // Extract vTPM AK public key
    let ak_pub = hcl_report.ak_pub()?;
    println!("AK Public Key ID: {:?}", ak_pub.key_id);

    // Get variable data hash
    let var_data_hash = hcl_report.var_data_sha256();
    println!("VarData SHA256: {:02x?}", var_data_hash);

    Ok(())
}
```

### PCR Operations

```rust
use vtpm_attestation::vtmp;
use sha2::{Sha256, Digest};

fn extend_measurement(measurement: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // Hash the measurement
    let mut hasher = Sha256::new();
    hasher.update(measurement);
    let digest: [u8; 32] = hasher.finalize().into();

    // Extend PCR 10 with the digest
    vtpm::extend_pcr(10, &digest)?;

    println!("Extended PCR 10 with measurement");
    Ok(())
}
```

## Platform Requirements

### Confidential Virtual Machines

This library is designed for confidential computing environments with:

- **Hardware TEE**: AMD SEV-SNP or Intel TDX support
- **vTPM 2.0**: Virtual TPM with attestation key provisioned
- **HCL Integration**: Host Compatibility Layer for report generation

### TPM Configuration

The library expects specific TPM handles and NV indices:

- **AK Handle**: `0x81000003` - vTPM Attestation Key
- **HCL Report NV Index**: `0x01400001` - HCL report storage
- **Report Data NV Index**: `0x01400002` - User data for reports
