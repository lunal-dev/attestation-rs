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
