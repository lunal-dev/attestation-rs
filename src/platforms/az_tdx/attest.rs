use crate::error::{AttestationError, Result};
use crate::utils::pad_report_data;

use super::evidence::AzTdxEvidence;

/// Check if Azure TDX platform is available.
pub fn is_available() -> bool {
    // Check Azure environment + TDX indicators
    is_azure_environment() && has_tdx_indicators()
}

fn is_azure_environment() -> bool {
    std::path::Path::new("/var/lib/hyperv/.kvp_pool_3").exists()
        || std::env::var("AZURE_INSTANCE_METADATA_SERVICE").is_ok()
}

fn has_tdx_indicators() -> bool {
    // On Azure TDX CVMs, there's no /dev/tdx_guest but the
    // vTPM and IMDS provide TDX attestation capabilities
    std::path::Path::new("/sys/kernel/config/tsm/report").exists()
}

/// Generate Azure TDX attestation evidence.
pub async fn generate_evidence(report_data: &[u8]) -> Result<AzTdxEvidence> {
    let _padded = pad_report_data(report_data, 64)?;

    // In a real implementation:
    // 1. az_tdx_vtpm::vtpm::get_report_with_report_data(&report_data) -> HCL report
    // 2. Parse HCL report -> extract TdReport
    // 3. az_tdx_vtpm::imds::get_td_quote(&td_report) -> TD quote
    // 4. az_tdx_vtpm::vtpm::get_quote(&report_data) -> TPM quote

    Err(AttestationError::HardwareAccessFailed(
        "Azure TDX attestation requires az-tdx-vtpm crate (not yet integrated)".to_string(),
    ))
}
