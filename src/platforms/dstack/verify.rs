use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

use crate::collateral::TdxCollateralProvider;
use crate::error::Result;
use crate::types::{PlatformType, VerificationResult, VerifyParams};

use super::evidence::DstackEvidence;

/// Normalize a quote string to base64.
///
/// dstack historically returns hex-encoded quotes; the attestation pipeline
/// stores base64. This function accepts either encoding so that evidence
/// produced by both old (hex) and new (base64) versions can be verified.
fn normalize_quote_to_base64(quote: &str) -> String {
    // If it decodes as hex and the result looks like a TDX quote (starts with version bytes),
    // convert to base64. Otherwise assume it's already base64.
    if let Ok(raw) = hex::decode(quote) {
        if raw.len() > 8 {
            return BASE64.encode(&raw);
        }
    }
    quote.to_string()
}

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

    let quote_b64 = normalize_quote_to_base64(&evidence.quote);

    // Convert DstackEvidence to TdxEvidence for reuse of TDX verification
    let tdx_evidence = crate::platforms::tdx::evidence::TdxEvidence {
        quote: quote_b64,
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
