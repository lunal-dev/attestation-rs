#[cfg(feature = "az-snp")]
pub mod az_snp;
#[cfg(feature = "az-tdx")]
pub mod az_tdx;
#[cfg(feature = "gcp-snp")]
pub mod gcp_snp;
#[cfg(feature = "gcp-tdx")]
pub mod gcp_tdx;
#[cfg(feature = "snp")]
pub mod snp;
#[cfg(feature = "tdx")]
pub mod tdx;
#[cfg(feature = "tpm")]
pub mod tpm;
#[cfg(any(feature = "az-snp", feature = "az-tdx", feature = "tpm"))]
pub mod tpm_common;
