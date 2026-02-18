use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL, Engine};

use crate::error::{AttestationError, Result};
use crate::platforms::tpm_common;
use crate::types::{PlatformType, VerificationResult, VerifyParams};

use super::evidence::AzTdxEvidence;

/// HCL report variable data offset (same as Azure SNP).
const HCL_REPORT_VARDATA_OFFSET: usize = 0x0880;

/// Verify Azure TDX vTPM attestation evidence.
pub async fn verify_evidence(
    evidence: &AzTdxEvidence,
    params: &VerifyParams,
) -> Result<VerificationResult> {
    // 1. Decode evidence components
    let hcl_report = BASE64URL
        .decode(&evidence.hcl_report)
        .map_err(|e| AttestationError::EvidenceDeserialize(format!("HCL report base64: {}", e)))?;

    let td_quote_bytes = BASE64URL
        .decode(&evidence.td_quote)
        .map_err(|e| AttestationError::EvidenceDeserialize(format!("TD quote base64: {}", e)))?;

    // 2. Parse TPM quote
    let (tpm_sig, tpm_msg, tpm_pcrs) = tpm_common::decode_tpm_quote(&evidence.tpm_quote)?;

    // 3. Extract HCL variable data
    let var_data = if hcl_report.len() > HCL_REPORT_VARDATA_OFFSET {
        &hcl_report[HCL_REPORT_VARDATA_OFFSET..]
    } else {
        &[]
    };

    // 4. TPM signature verification
    let tpm_sig_valid = tpm_common::verify_tpm_signature(&tpm_sig, &tpm_msg, var_data)?;

    // 5. TPM nonce check
    let tpm_nonce_match = if let Some(expected) = &params.expected_report_data {
        Some(tpm_common::verify_tpm_nonce(&tpm_msg, expected)?)
    } else {
        None
    };

    // 6. TPM PCR integrity
    tpm_common::verify_tpm_pcrs(&tpm_msg, &tpm_pcrs)?;

    // 7. TDX DCAP quote verification
    let tdx_quote = crate::platforms::tdx::verify::parse_tdx_quote(&td_quote_bytes)?;

    // 8. HCL var_data binding: td_quote.report_data == SHA-384(hcl_var_data)
    let var_data_hash = crate::utils::sha384(var_data);
    let hcl_binding_valid =
        crate::utils::constant_time_eq(&tdx_quote.body.report_data[..48], &var_data_hash);

    if !hcl_binding_valid {
        return Err(AttestationError::SignatureVerificationFailed(
            "HCL var_data binding failed: TDX quote report_data != SHA-384(var_data)".to_string(),
        ));
    }

    // 9. Init data check: expected_init_data_hash vs PCR[8]
    let init_data_match = params.expected_init_data_hash.as_ref().map(|expected| {
        if tpm_pcrs.len() > 8 {
            let mut padded = vec![0u8; 32];
            let len = expected.len().min(32);
            padded[..len].copy_from_slice(&expected[..len]);
            crate::utils::constant_time_eq(&tpm_pcrs[8], &padded)
        } else {
            false
        }
    });

    // 10. Extract TDX claims + TPM PCR values
    let tdx_claims = crate::platforms::tdx::claims::extract_claims(&tdx_quote);
    let mut platform_data = tdx_claims.platform_data.clone();

    // Add TPM PCR values
    let pcr_map: serde_json::Value = tpm_pcrs
        .iter()
        .enumerate()
        .map(|(i, pcr)| {
            (
                format!("pcr{:02}", i),
                serde_json::Value::String(hex::encode(pcr)),
            )
        })
        .collect::<serde_json::Map<String, serde_json::Value>>()
        .into();
    platform_data["tpm"] = pcr_map;

    let claims = crate::types::Claims {
        platform_data,
        ..tdx_claims
    };

    Ok(VerificationResult {
        signature_valid: tpm_sig_valid && hcl_binding_valid,
        platform: PlatformType::AzTdx,
        claims,
        report_data_match: tpm_nonce_match,
        init_data_match,
    })
}
