use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL, Engine};

use crate::error::{AttestationError, Result};
use crate::utils::pad_report_data;

use super::evidence::AzSnpEvidence;

/// Check if Azure SNP platform is available.
pub fn is_available() -> bool {
    // Check Azure IMDS availability + SEV-SNP platform device
    std::path::Path::new("/sys/devices/platform/sev-guest").exists()
        && is_azure_imds_available()
}

fn is_azure_imds_available() -> bool {
    // Quick check for Azure environment
    std::path::Path::new("/var/lib/hyperv/.kvp_pool_3").exists()
        || std::env::var("AZURE_INSTANCE_METADATA_SERVICE").is_ok()
}

/// Generate Azure SNP attestation evidence.
pub async fn generate_evidence(report_data: &[u8]) -> Result<AzSnpEvidence> {
    let _padded = pad_report_data(report_data, 64)?;

    // In a real implementation, these would call:
    // 1. az_snp_vtpm::vtpm::get_report() -> HCL report bytes
    // 2. az_snp_vtpm::vtpm::get_quote(&report_data) -> TPM quote
    // 3. az_snp_vtpm::imds::get_certs() -> VCEK PEM -> convert to DER

    // For now, return an error since we can't import az-snp-vtpm directly
    // (it has heavy native dependencies). On a real Azure SNP CVM, this
    // would use the vTPM and IMDS APIs.

    Err(AttestationError::HardwareAccessFailed(
        "Azure SNP attestation requires az-snp-vtpm crate (not yet integrated)".to_string(),
    ))
}
