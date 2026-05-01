use crate::error::{AttestationError, Result};
use crate::platforms::tpm_common;
use crate::types::{Claims, PlatformType, TcbInfo, VerifyParams};

use super::evidence::TpmEvidence;

/// Verify bare-metal TPM attestation evidence.
///
/// Trust model: the caller trusts the AK public key included in the evidence.
/// For stronger platform identity, verify the optional EK certificate chain
/// against TPM manufacturer roots.
pub async fn verify_evidence(
    evidence: &TpmEvidence,
    params: &VerifyParams,
) -> Result<crate::types::VerificationResult> {
    if evidence.version != 1 {
        return Err(AttestationError::EvidenceDeserialize(format!(
            "unsupported TPM evidence version: {}",
            evidence.version
        )));
    }

    let (tpm_sig, tpm_msg, tpm_pcrs) = tpm_common::decode_tpm_quote(&evidence.tpm_quote)?;

    let ak_pub_bytes = hex::decode(&evidence.ak_pub)
        .map_err(|e| AttestationError::EvidenceDeserialize(format!("invalid ak_pub hex: {e}")))?;

    // verify_tpm_signature falls back to TPM2B_PUBLIC parsing when JWK fails,
    // which is always the case for raw TPM2B_PUBLIC bytes.
    tpm_common::verify_tpm_signature(&tpm_sig, &tpm_msg, &ak_pub_bytes)?;
    tpm_common::verify_tpm_pcrs(&tpm_msg, &tpm_pcrs)?;

    let report_data_match =
        tpm_common::check_report_data(&tpm_msg, params.expected_report_data.as_deref())?;

    let firmware_version = tpm_common::extract_firmware_version(&tpm_msg).unwrap_or(0);
    let nonce = tpm_common::extract_tpm_nonce(&tpm_msg).unwrap_or_default();

    let signed_data = nonce.clone();
    let base_claims = Claims {
        launch_digest: String::new(),
        report_data: nonce,
        signed_data,
        init_data: Vec::new(),
        tcb: TcbInfo::Tpm { firmware_version },
        platform_data: serde_json::json!({}),
    };

    Ok(tpm_common::build_tpm_verification_result(
        base_claims,
        &tpm_pcrs,
        &tpm_msg,
        PlatformType::Tpm,
        report_data_match,
        None,  // no init_data for bare-metal TPM
        false, // no collateral verification
    ))
}
