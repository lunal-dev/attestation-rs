# amd-vtpm

A Rust library for vTPM-based SEV-SNP attestation for Confidential Virtual Machines. This crate enables secure attestation flows by leveraging AMD's Secure Encrypted Virtualization (SEV) with Secure Nested Paging (SNP) technology and virtual Trusted Platform Module (vTPM) capabilities.

## Features

- **SEV-SNP Report Generation**: Retrieve and validate AMD SEV-SNP attestation reports
- **vTPM Integration**: Generate TPM quotes with attestation keys linked to SNP reports
- **Certificate Management**: Fetch and validate VCEK certificates from AMD KDS or Azure IMDS
- **Cryptographic Verification**: Support for RSA and ECDSA signature verification (P-256/P-384)
- **Azure CVM Support**: Optimized for Azure Confidential Virtual Machines

## Architecture

The vTPM is cryptographically linked to the SEV-SNP report via the vTPM Attestation Key (AK). The public AK is included in Runtime Data, which is hashed and submitted as Report Data when generating the SNP report. This provides a verifiable chain of trust from the hardware-backed SEV-SNP report to vTPM-generated quotes.

```
                              ┌────────────────────────┐
                              │ HCL Data               │
                              │                        │
                              │ ┌──────────────────────┴─┐  ─┐
                              │ │ Runtime Data           │   │
                              │ │                        │   │
    ┌──────────────────────┐  │ │ ┌────────────────────┐ │   ├─┐
  ┌─┤ vTPM AK              ├──┼─┼─┤ vTPM Public AK     │ │   │ │
  │ └──────────────────────┘  │ │ └────────────────────┘ │   │ │
  │         ┌──────────────┐  │ └──────────────────────┬─┘  ─┘ │
  │         │ vTPM Quote   │  │ ┌────────────────────┐ │       │
  │         │              │  │ │ HCL Report         │ │       │
signs ┌─  ┌─┴────────────┐ │  │ │                    │ │     sha256
  │   │   │ Message      │ │  │ │ ┌────────────────┐ │ │       │
  │   │   │              │ │  │ │ │ SEV-SNP Report │ │ │       │
  │   │   │ ┌──────────┐ │ │  │ │ │                │ │ │       │
  │   │   │ │ PCR0     │ │ │  │ │ │ ┌──────────────┴─┴─┴─┐     │
  │   │   │ └──────────┘ │ │  │ │ │ │ Report Data        │ ◄───┘
  │   │   │   ...        │ │  │ │ │ └──────────────┬─┬─┬─┘
  │   │   │ ┌──────────┐ │ │  │ │ └────────────────┘ │ │
  └─► │   │ │ PCRn     │ │ │  │ └────────────────────┘ │
      │   │ └──────────┘ │ │  └────────────────────────┘
      │   │ ┌──────────┐ │ │
      │   │ │ Nonce    │ │ │
      │   │ └──────────┘ │ │
      └─  └─┬────────────┘ │
            └──────────────┘
```

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
amd-vtpm = "0.1.0"
```

### Features

- `attester` - Enable attestation generation capabilities (requires TPM access)
- `verifier` - Enable attestation verification capabilities (default)
- `integration_test` - Enable integration tests (requires SEV-SNP CVM)

```toml
[dependencies]
amd-vtpm = { git = "https://github.com/lunal-dev/lunal-attestation.git" }
```

## Usage

### Library Usage

#### Basic Attestation (Verifier)

```rust
use amd_vtpm::{report, amd_kds, certs::Vcek, imds};
use amd_vtpm::report::{AttestationReport, Validateable};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get certificates from Azure IMDS
    let certificates = imds::get_certs().await?;
    let vcek = Vcek::from_pem(&certificates.vcek)?;

    // Or fetch from AMD KDS
    // let cert_chain = amd_kds::get_cert_chain().await?;
    // let vcek = amd_kds::get_vcek(&snp_report).await?;

    // Parse and validate report
    let report_bytes = std::fs::read("report.bin")?;
    let snp_report = report::parse(&report_bytes)?;

    // Validate certificate chain and report
    cert_chain.validate()?;
    vcek.validate(&cert_chain)?;
    snp_report.validate(&vcek)?;

    println!("Report validation successful!");
    Ok(())
}
```

#### Attestation Generation (Attester)

```rust
use amd_vtpm::{vtpm, hcl::HclReport, report::AttestationReport};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Check if running on SEV-SNP CVM
    if amd_vtpm::is_snp_cvm()? {
        // Generate attestation report
        let report_bytes = vtpm::get_report()?;
        let hcl_report = HclReport::new(report_bytes)?;
        let snp_report: AttestationReport = hcl_report.try_into()?;

        // Generate vTPM quote with nonce
        let nonce = "challenge_data".as_bytes();
        let quote = vtpm::get_quote(nonce)?;

        println!("Generated attestation evidence successfully!");
    }
    Ok(())
}
```

### Binary Usage

The crate includes a command-line tool `snp-vtpm` for direct attestation operations:

#### Build & Install

```bash
cargo build --release -p amd-vtpm --features="attester,verifier"
```

#### Usage Examples

Retrieve and validate SEV-SNP report:
```bash
sudo ./snp-vtpm report --print --imds
```

Generate vTPM quote with nonce:
```bash
sudo ./snp-vtpm quote --nonce "my_challenge_data"
```

### Example Project

The `./example` directory contains a complete Remote Attestation flow demonstration:

```bash
cd example
cargo build --features attester
cargo run --features attester
```

## Testing

### Unit Tests

```bash
cargo test
```

### Integration Tests

Integration tests require running on an actual SEV-SNP CVM with root privileges:

```bash
# On SEV-SNP CVM
sudo -E env "PATH=$PATH" cargo test --features integration_test -- --test-threads 1
```

## Azure CVM Deployment

### Create Confidential VM

```bash
export IMAGE_ID=/subscriptions/.../resourceGroups/.../providers/Microsoft.Compute/galleries/.../images/.../versions/1.0.0
make deploy  # Uses Ubuntu 22.04 CVM image
```

### Deploy Binary

```bash
cargo build --release -p amd-vtpm --features="attester,verifier"
scp target/release/snp-vtpm azureuser@$CONFIDENTIAL_VM:
```

## Certificate Sources

### AMD Key Distribution Service (KDS)

Certificates fetched directly from AMD's public KDS:
- **VCEK**: Retrieved using chip ID and TCB levels from SNP report
- **Chain**: ASK (AMD SEV Key) and ARK (AMD Root Key)
- **URL**: `https://kdsintf.amd.com/vcek/v1/Milan/`

### Azure IMDS

Certificates provided by Azure for the specific CVM instance:
- **Endpoint**: `http://169.254.169.254/metadata/THIM/amd/certification`
- **Requires**: `Metadata: true` header
- **Format**: JSON with PEM-encoded certificates
