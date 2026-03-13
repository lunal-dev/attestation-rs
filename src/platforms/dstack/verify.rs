use crate::collateral::TdxCollateralProvider;
use crate::error::Result;
use crate::types::{PlatformType, VerificationResult, VerifyParams};

use super::evidence::DstackEvidence;

/// Verify dstack TDX attestation evidence.
///
/// Since dstack produces standard Intel TDX v4/v5 quotes, verification
/// is delegated to the existing TDX DCAP verification pipeline. The only
/// difference is that the result is tagged with `PlatformType::Dstack`.
pub async fn verify_evidence(
    evidence: &DstackEvidence,
    params: &VerifyParams,
    collateral_provider: Option<&dyn TdxCollateralProvider>,
) -> Result<VerificationResult> {
    // Validate field sizes
    crate::utils::check_field_size("quote", evidence.quote.len())?;

    // Convert DstackEvidence to TdxEvidence for reuse of TDX verification
    let tdx_evidence = crate::platforms::tdx::evidence::TdxEvidence {
        quote: evidence.quote.clone(),
        // dstack's event_log is in a different format than the CC eventlog
        // from ACPI CCEL, so we don't pass it through to TDX verification
        cc_eventlog: None,
    };

    let mut result =
        crate::platforms::tdx::verify::verify_evidence(&tdx_evidence, params, collateral_provider)
            .await?;

    // Re-tag the platform as Dstack
    result.platform = PlatformType::Dstack;

    Ok(result)
}
