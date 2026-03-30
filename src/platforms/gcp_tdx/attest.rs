// INVARIANT CLASS: Correctness
// This module detects the GCP platform and delegates TDX attestation to the
// bare-metal TDX implementation. GCP exposes the same ConfigFS TSM interface
// (or /dev/tdx_guest) and produces standard Intel DCAP quotes.

use crate::error::Result;
use crate::platforms::tdx::evidence::TdxEvidence;

const DMI_BOARD_VENDOR_PATH: &str = "/sys/class/dmi/id/board_vendor";

/// Check if we are running on a GCP Confidential VM with TDX.
///
/// Detection: TDX hardware must be present AND the DMI board vendor must be Google.
/// This matches the approach used by Google's go-tpm-tools for GCP detection.
///
/// # Security
///
/// This is a **best-effort heuristic**, not a security boundary. DMI/SMBIOS
/// data is provided by the hypervisor and can be spoofed by a malicious host.
/// A compromised host that sets `board_vendor = "Google"` on non-GCP hardware
/// will cause this function to return `true`. The resulting attestation quote
/// is cryptographically valid Intel TDX DCAP evidence, but the `GcpTdx`
/// platform tag in the envelope reflects the attester's self-classification only.
pub fn is_available() -> bool {
    if !crate::platforms::tdx::attest::is_available() {
        return false;
    }
    match std::fs::read_to_string(DMI_BOARD_VENDOR_PATH) {
        Ok(vendor) => vendor.trim() == "Google",
        Err(e) => {
            log::warn!("GCP TDX detection: failed to read {DMI_BOARD_VENDOR_PATH}: {e}");
            false
        }
    }
}

/// Generate GCP TDX attestation evidence with default quote method.
///
/// Delegates to the bare-metal TDX implementation — GCP uses the same
/// ConfigFS TSM interface and standard Intel DCAP quotes.
pub async fn generate_evidence(report_data: &[u8]) -> Result<TdxEvidence> {
    crate::platforms::tdx::attest::generate_evidence(report_data).await
}

/// Generate GCP TDX attestation evidence with explicit quote method.
///
/// On GCP, vsock to a host-side QGS is typically not available — use
/// [`TdxQuoteMethod::ConfigFs`] or [`TdxQuoteMethod::Auto`] (which will
/// fall back to ConfigFS when vsock fails).
pub async fn generate_evidence_with(
    report_data: &[u8],
    method: crate::platforms::tdx::attest::TdxQuoteMethod,
) -> Result<TdxEvidence> {
    crate::platforms::tdx::attest::generate_evidence_with(report_data, method).await
}
