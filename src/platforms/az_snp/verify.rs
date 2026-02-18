use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL, Engine};

use crate::collateral::CertProvider;
use crate::error::{AttestationError, Result};
use crate::platforms::tpm_common;
use crate::types::{PlatformType, VerificationResult, VerifyParams};

use super::evidence::AzSnpEvidence;

/// SNP HCL report fixed offsets.
const HCL_REPORT_SNP_OFFSET: usize = 0x20;
const HCL_REPORT_VARDATA_OFFSET: usize = 0x0880;

/// Verify Azure SNP vTPM attestation evidence.
pub async fn verify_evidence(
    evidence: &AzSnpEvidence,
    params: &VerifyParams,
    cert_provider: &dyn CertProvider,
) -> Result<VerificationResult> {
    // 1. Decode HCL report
    let hcl_report = BASE64URL
        .decode(&evidence.hcl_report)
        .map_err(|e| AttestationError::EvidenceDeserialize(format!("HCL report base64: {}", e)))?;

    // 2. Decode VCEK
    let vcek_der = BASE64URL
        .decode(&evidence.vcek)
        .map_err(|e| AttestationError::EvidenceDeserialize(format!("VCEK base64: {}", e)))?;

    // 3. Parse TPM quote
    let (tpm_sig, tpm_msg, tpm_pcrs) = tpm_common::decode_tpm_quote(&evidence.tpm_quote)?;

    // 4. Extract SNP report from HCL report
    if hcl_report.len() < HCL_REPORT_SNP_OFFSET + 1184 {
        return Err(AttestationError::QuoteParseFailed(
            "HCL report too short to contain SNP report".to_string(),
        ));
    }

    let snp_report_bytes = &hcl_report[HCL_REPORT_SNP_OFFSET..HCL_REPORT_SNP_OFFSET + 1184];
    let snp_report = crate::platforms::snp::verify::SnpReport::from_bytes(snp_report_bytes)?;

    // 5. Extract HCL variable data for binding check
    let var_data = if hcl_report.len() > HCL_REPORT_VARDATA_OFFSET {
        &hcl_report[HCL_REPORT_VARDATA_OFFSET..]
    } else {
        &[]
    };

    // 6. TPM signature verification
    let tpm_sig_valid = tpm_common::verify_tpm_signature(&tpm_sig, &tpm_msg, var_data)?;

    // 7. TPM nonce check
    let tpm_nonce_match = if let Some(expected) = &params.expected_report_data {
        Some(tpm_common::verify_tpm_nonce(&tpm_msg, expected)?)
    } else {
        None
    };

    // 8. TPM PCR integrity
    tpm_common::verify_tpm_pcrs(&tpm_msg, &tpm_pcrs)?;

    // 9. HCL var_data binding: SNP report's report_data == SHA-256(hcl_var_data)
    let var_data_hash = crate::utils::sha256(var_data);
    let hcl_binding_valid =
        crate::utils::constant_time_eq(&snp_report.report_data[..32], &var_data_hash);

    if !hcl_binding_valid {
        return Err(AttestationError::SignatureVerificationFailed(
            "HCL var_data binding failed: SNP report_data != SHA-256(var_data)".to_string(),
        ));
    }

    // 10. VCEK validation against bundled AMD CA chain
    let processor_gen = crate::types::ProcessorGeneration::from_cpuid(
        snp_report.cpuid_fam_id,
        snp_report.cpuid_mod_id,
    )
    .ok_or_else(|| {
        AttestationError::QuoteParseFailed(format!(
            "unknown processor: family=0x{:02X}, model=0x{:02X}",
            snp_report.cpuid_fam_id, snp_report.cpuid_mod_id
        ))
    })?;

    let (ark_der, ask_der) = cert_provider.get_snp_cert_chain(processor_gen).await?;
    crate::platforms::snp::verify::verify_cert_chain_pub(&ark_der, &ask_der, &vcek_der)?;

    // 11. VMPL check
    if snp_report.vmpl != 0 {
        return Err(AttestationError::VmplCheckFailed(snp_report.vmpl));
    }

    // 12. Init data check: expected_init_data_hash vs PCR[8]
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

    // 13. Extract claims
    let snp_claims = crate::platforms::snp::claims::extract_claims(&snp_report);
    let mut platform_data = snp_claims.platform_data.clone();

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
        ..snp_claims
    };

    Ok(VerificationResult {
        signature_valid: tpm_sig_valid && hcl_binding_valid,
        platform: PlatformType::AzSnp,
        claims,
        report_data_match: tpm_nonce_match,
        init_data_match,
    })
}
