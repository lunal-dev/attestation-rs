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
        || std::path::Path::new("/var/lib/waagent").exists()
        || std::env::var("AZURE_INSTANCE_METADATA_SERVICE").is_ok()
}

fn has_tdx_indicators() -> bool {
    // On Azure TDX CVMs, the HCL report in TPM NVRAM has report_type=4 (TDX).
    // Also check for the tdx_guest device or TSM provider indicating TDX.
    std::path::Path::new("/dev/tdx_guest").exists()
        || check_tsm_provider_is_tdx()
}

fn check_tsm_provider_is_tdx() -> bool {
    // Check if any TSM report entry has provider "tdx_guest"
    let report_dir = std::path::Path::new("/sys/kernel/config/tsm/report");
    if let Ok(entries) = std::fs::read_dir(report_dir) {
        for entry in entries.flatten() {
            let provider_path = entry.path().join("provider");
            if let Ok(provider) = std::fs::read_to_string(provider_path) {
                if provider.trim() == "tdx_guest" {
                    return true;
                }
            }
        }
    }
    false
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
