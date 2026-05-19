// INVARIANT CLASS: Correctness
// This module detects the GCP platform and delegates SNP attestation to the
// bare-metal SNP implementation. GCP exposes the same /dev/sev-guest device
// and produces standard AMD SNP attestation reports.

use std::path::Path;

use crate::error::Result;
use crate::platforms::snp::evidence::SnpEvidence;

/// SNP guest attestation character device — the device attestation opens.
const SEV_GUEST_DEVICE_PATH: &str = "/dev/sev-guest";
const DMI_BOARD_VENDOR_PATH: &str = "/sys/class/dmi/id/board_vendor";

/// Check if we are running on a GCP Confidential VM with SNP.
///
/// Detection: SNP hardware must be present AND the DMI board vendor must be Google.
/// This matches the approach used by Google's go-tpm-tools for GCP detection.
///
/// # Security
///
/// This is a **best-effort heuristic**, not a security boundary. DMI/SMBIOS
/// data is provided by the hypervisor and can be spoofed by a malicious host.
/// A compromised host that sets `board_vendor = "Google"` on non-GCP hardware
/// will cause this function to return `true`. The resulting attestation report
/// is cryptographically valid AMD SNP evidence, but the `GcpSnp` platform tag
/// in the envelope reflects the attester's self-classification only.
pub fn is_available() -> bool {
    if !Path::new(SEV_GUEST_DEVICE_PATH).exists() {
        return false;
    }
    match std::fs::read_to_string(DMI_BOARD_VENDOR_PATH) {
        Ok(vendor) => vendor.trim() == "Google",
        Err(e) => {
            log::warn!("GCP SNP detection: failed to read {DMI_BOARD_VENDOR_PATH}: {e}");
            false
        }
    }
}

/// Generate GCP SNP attestation evidence.
///
/// Delegates to the bare-metal SNP implementation — GCP uses the same
/// /dev/sev-guest device and standard AMD SNP attestation reports.
pub async fn generate_evidence(report_data: &[u8]) -> Result<SnpEvidence> {
    crate::platforms::snp::attest::generate_evidence(report_data).await
}
