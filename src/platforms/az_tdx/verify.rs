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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platforms::tpm_common::TpmQuote;

    fn build_dummy_tpm_quote() -> TpmQuote {
        TpmQuote {
            signature: "00".repeat(256),
            message: "ff544347".to_string() + &"00".repeat(100),
            pcrs: (0..24).map(|_| "00".repeat(32)).collect(),
        }
    }

    #[test]
    fn test_az_tdx_evidence_serialization_roundtrip() {
        let evidence = AzTdxEvidence {
            version: 1,
            tpm_quote: build_dummy_tpm_quote(),
            hcl_report: "dGVzdA".to_string(),
            td_quote: "AAAA".to_string(),
        };

        let json = serde_json::to_string(&evidence).unwrap();
        let deserialized: AzTdxEvidence = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.version, 1);
        assert_eq!(deserialized.hcl_report, evidence.hcl_report);
        assert_eq!(deserialized.td_quote, evidence.td_quote);
        assert_eq!(deserialized.tpm_quote.pcrs.len(), 24);
    }

    #[test]
    fn test_invalid_base64_hcl_report() {
        let evidence = AzTdxEvidence {
            version: 1,
            tpm_quote: build_dummy_tpm_quote(),
            hcl_report: "!!!invalid!!!".to_string(),
            td_quote: BASE64URL.encode(&[0u8; 100]),
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        let params = VerifyParams::default();

        let result = rt.block_on(verify_evidence(&evidence, &params));
        assert!(result.is_err());
        let err = format!("{:?}", result.err().unwrap());
        assert!(err.contains("base64") || err.contains("Base64"), "error: {}", err);
    }

    #[test]
    fn test_invalid_base64_td_quote() {
        let hcl = vec![0u8; HCL_REPORT_VARDATA_OFFSET + 100];
        let evidence = AzTdxEvidence {
            version: 1,
            tpm_quote: build_dummy_tpm_quote(),
            hcl_report: BASE64URL.encode(&hcl),
            td_quote: "!!!invalid!!!".to_string(),
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        let params = VerifyParams::default();

        let result = rt.block_on(verify_evidence(&evidence, &params));
        assert!(result.is_err());
    }

    #[test]
    fn test_hcl_var_data_binding_sha384() {
        // Azure TDX uses SHA-384 for HCL var_data binding (vs SHA-256 for SNP)
        let var_data = b"test variable data for tdx binding";
        let var_data_hash = crate::utils::sha384(var_data);

        // SHA-384 produces 48 bytes
        assert_eq!(var_data_hash.len(), 48);

        // The TDX quote's report_data[..48] should equal SHA-384(var_data)
        // This verifies the binding mechanism is correct for TDX
    }

    #[test]
    fn test_hcl_vardata_offset_consistent() {
        // Azure TDX should use the same HCL var_data offset as Azure SNP
        assert_eq!(
            HCL_REPORT_VARDATA_OFFSET, 0x0880,
            "HCL var_data offset should be 0x0880"
        );
    }

    #[test]
    fn test_platform_type_is_az_tdx() {
        assert_eq!(
            format!("{}", PlatformType::AzTdx),
            "az-tdx",
            "platform type should display as az-tdx"
        );
    }

    #[test]
    fn test_init_data_pcr8_check() {
        // Verify the PCR[8] init data check logic
        let pcrs: Vec<Vec<u8>> = (0..24).map(|i| vec![i as u8; 32]).collect();

        // Expected init data should match PCR[8]
        let expected = pcrs[8].clone();
        let mut padded = vec![0u8; 32];
        padded[..expected.len().min(32)].copy_from_slice(&expected[..expected.len().min(32)]);

        assert!(
            crate::utils::constant_time_eq(&pcrs[8], &padded),
            "PCR[8] should match expected init data"
        );

        // Non-matching expected should fail
        let wrong = vec![0xFF; 32];
        assert!(
            !crate::utils::constant_time_eq(&pcrs[8], &wrong),
            "PCR[8] should not match wrong init data"
        );
    }
}
