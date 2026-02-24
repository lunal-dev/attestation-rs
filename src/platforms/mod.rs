#[cfg(feature = "snp")]
pub mod snp;
#[cfg(feature = "tdx")]
pub mod tdx;
#[cfg(any(feature = "az-snp", feature = "az-tdx"))]
pub mod tpm_common;
#[cfg(feature = "az-snp")]
pub mod az_snp;
#[cfg(feature = "az-tdx")]
pub mod az_tdx;
