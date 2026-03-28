// INVARIANT CLASS: Correctness
// GCP SNP verification delegates entirely to the bare-metal SNP verifier.
// The only difference is the platform tag in the result, which allows
// callers to distinguish GCP-originated evidence for policy decisions.
//
// SECURITY NOTE: The `GcpSnp` platform tag in VerificationResult reflects
// what the *attester* claimed, not a cryptographic proof of GCP origin.
// The AMD SNP attestation report does not contain cloud-provider identity.
// Policy engines should NOT grant elevated trust based solely on the
// `GcpSnp` tag — use report fields (measurement, chip_id, TCB) instead.

use crate::collateral::CertProvider;
use crate::error::Result;
use crate::platforms::snp::evidence::SnpEvidence;
use crate::types::{PlatformType, VerificationResult, VerifyParams};

/// Verify GCP SNP attestation evidence.
///
/// Delegates to the bare-metal SNP verification pipeline and overrides the
/// platform tag to `GcpSnp`. The attestation report format, certificate chain,
/// and all cryptographic verification are identical to bare-metal SNP.
///
/// **Note:** The `GcpSnp` platform tag reflects the attester's claim, not a
/// cryptographic proof of GCP origin. Policy decisions should use report
/// fields (measurement, chip_id, TCB) rather than the platform tag alone.
pub async fn verify_evidence(
    evidence: &SnpEvidence,
    params: &VerifyParams,
    cert_provider: &dyn CertProvider,
) -> Result<VerificationResult> {
    let mut result =
        crate::platforms::snp::verify::verify_evidence(evidence, params, cert_provider).await?;
    result.platform = PlatformType::GcpSnp;
    Ok(result)
}
