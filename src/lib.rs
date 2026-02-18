//! Unified TEE attestation evidence generation and verification.
//!
//! This library provides a single interface for generating and verifying
//! attestation evidence across multiple Trusted Execution Environment (TEE)
//! platforms: AMD SEV-SNP, Intel TDX, Azure SEV-SNP (vTPM), and Azure TDX (vTPM).
//!
//! # Platform Support
//!
//! Each platform is enabled via feature flags (`snp`, `tdx`, `az-snp`, `az-tdx`).
//! Verification is always available when a platform feature is enabled.
//! Evidence generation requires the `attest` feature and appropriate hardware.
//!
//! # Quick Start
//!
//! **Verifier** (any machine, including WASM):
//! ```rust,ignore
//! use attestation::platforms::snp::Snp;
//! use attestation::platforms::Platform;
//!
//! let snp = Snp::with_default_provider();
//! let result = snp.verify(&evidence, &params).await?;
//! assert!(result.signature_valid);
//! ```
//!
//! **Attester** (inside TEE, with `attest` feature):
//! ```rust,ignore
//! let platform = attestation::detect()?;
//! let evidence_json = platform.attest_json(b"nonce").await?;
//! ```

pub mod error;
pub mod types;
pub mod platforms;
pub mod collateral;
pub mod utils;

pub use error::{AttestationError, Result};
pub use types::*;
pub use platforms::{Platform, ErasedPlatform};
pub use collateral::{CertProvider, DefaultCertProvider};

/// Detect the current TEE platform and return a boxed Platform impl.
/// Checks Azure variants first (they also have bare-metal device paths),
/// then bare-metal variants.
/// Only checks platforms whose features are enabled.
#[cfg(feature = "attest")]
pub fn detect() -> Result<Box<dyn ErasedPlatform>> {
    // 1. Check Azure TDX
    #[cfg(feature = "az-tdx")]
    {
        if platforms::az_tdx::attest::is_available() {
            return Ok(Box::new(platforms::az_tdx::AzTdx::new()));
        }
    }

    // 2. Check Azure SNP
    #[cfg(feature = "az-snp")]
    {
        if platforms::az_snp::attest::is_available() {
            return Ok(Box::new(platforms::az_snp::AzSnp::with_default_provider()));
        }
    }

    // 3. Check bare-metal TDX
    #[cfg(feature = "tdx")]
    {
        if platforms::tdx::attest::is_available() {
            return Ok(Box::new(platforms::tdx::Tdx::new()));
        }
    }

    // 4. Check bare-metal SNP
    #[cfg(feature = "snp")]
    {
        if platforms::snp::attest::is_available() {
            return Ok(Box::new(platforms::snp::Snp::with_default_provider()));
        }
    }

    Err(AttestationError::NoPlatformDetected)
}
