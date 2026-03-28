// INVARIANT CLASS: Correctness
// This module detects the GCP platform and delegates SNP attestation to the
// bare-metal SNP implementation. GCP exposes the same /dev/sev-guest device
// and produces standard AMD SNP attestation reports.

use crate::error::Result;
use crate::platforms::snp::evidence::SnpEvidence;

const SEV_PLATFORM_PATH: &str = "/sys/devices/platform/sev-guest";
const DMI_BOARD_VENDOR_PATH: &str = "/sys/class/dmi/id/board_vendor";

/// Check if we are running on a GCP Confidential VM with SNP.
///
/// Detection: SNP hardware must be present AND the DMI board vendor must be Google.
/// This matches the approach used by Google's go-tpm-tools for GCP detection.
pub fn is_available() -> bool {
    if !std::path::Path::new(SEV_PLATFORM_PATH).exists() {
        return false;
    }
    match std::fs::read_to_string(DMI_BOARD_VENDOR_PATH) {
        Ok(vendor) => vendor.trim() == "Google",
        Err(_) => false,
    }
}

/// Generate GCP SNP attestation evidence.
///
/// Delegates to the bare-metal SNP implementation — GCP uses the same
/// /dev/sev-guest device and standard AMD SNP attestation reports.
pub async fn generate_evidence(report_data: &[u8]) -> Result<SnpEvidence> {
    crate::platforms::snp::attest::generate_evidence(report_data).await
}
