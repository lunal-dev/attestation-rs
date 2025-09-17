# Lunal Attestation Tooling

A Rust workspace providing comprehensive libraries and CLI tools for confidential computing attestation across multiple Trusted Execution Environment (TEE) platforms.

## Overview

This workspace contains three specialized crates that work together to provide complete attestation workflows for confidential computing environments. The tooling supports both attestation generation within TEEs and verification by relying parties.

## Workspace Members

### [`lunal-attestation`](lunal-attestation/)
Multi-platform attestation toolkit with Intel TDX support, WebAssembly deployment capabilities, and unified CLI tools. Provides Intel PCS integration for certificate fetching and DCAP v4 quote verification.

### [`amd-vtpm`](amd-vtpm/)
AMD SEV-SNP attestation library with vTPM integration. Handles SEV-SNP report parsing, certificate chain validation, and cryptographic verification with support for both local and remote certificate sources.

### [`vtpm-attestation`](vtpm-attestation/)
Platform-agnostic vTPM operations and Host Compatibility Layer (HCL) report processing. Provides core TPM functionality, quote generation, PCR operations, and multi-platform TEE report parsing for both AMD SEV-SNP and Intel TDX.

## Installation from Git

Add the required crates to your `Cargo.toml`:

```toml
[dependencies]
# Multi-platform attestation with Intel TDX
lunal-attestation = { git = "https://github.com/lunal-dev/lunal-attestation" }

# AMD SEV-SNP attestation
amd-vtpm = { git = "https://github.com/lunal-dev/lunal-attestation" }

# Platform-agnostic vTPM operations
vtpm-attestation = { git = "https://github.com/lunal-dev/lunal-attestation" }
```


## License

Licensed under the MIT License.