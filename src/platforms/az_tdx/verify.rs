use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL, Engine};

use crate::error::{AttestationError, Result};
use crate::platforms::tpm_common;
use crate::types::{PlatformType, VerificationResult, VerifyParams};

use super::evidence::AzTdxEvidence;

/// Decode URL-safe base64, tolerating optional padding.
fn decode_base64url(input: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    BASE64URL.decode(input.trim_end_matches('='))
}

/// Verify Azure TDX vTPM attestation evidence.
pub async fn verify_evidence(
    evidence: &AzTdxEvidence,
    params: &VerifyParams,
) -> Result<VerificationResult> {
    // 1. Decode HCL report
    let hcl_report_bytes = decode_base64url(&evidence.hcl_report)
        .map_err(|e| AttestationError::EvidenceDeserialize(format!("HCL report base64: {}", e)))?;

    // 2. Parse HCL report structure (extracts TEE report + var_data JSON)
    let hcl = tpm_common::parse_hcl_report(&hcl_report_bytes)?;

    // 3. Decode TD quote
    let td_quote_bytes = decode_base64url(&evidence.td_quote)
        .map_err(|e| AttestationError::EvidenceDeserialize(format!("TD quote base64: {}", e)))?;

    // 4. Parse TPM quote
    let (tpm_sig, tpm_msg, tpm_pcrs) = tpm_common::decode_tpm_quote(&evidence.tpm_quote)?;

    // 5. TPM signature verification (AK pub key extracted from var_data JWK JSON)
    let tpm_sig_valid = tpm_common::verify_tpm_signature(&tpm_sig, &tpm_msg, &hcl.var_data)?;

    // 6. TPM nonce check (H2: enforce match)
    let tpm_nonce_match = if let Some(expected) = &params.expected_report_data {
        let matched = tpm_common::verify_tpm_nonce(&tpm_msg, expected)?;
        if !matched {
            return Err(AttestationError::ReportDataMismatch);
        }
        Some(true)
    } else {
        None
    };

    // 7. TPM PCR integrity
    tpm_common::verify_tpm_pcrs(&tpm_msg, &tpm_pcrs)?;

    // 8. TDX DCAP quote verification
    let tdx_quote = crate::platforms::tdx::verify::parse_tdx_quote(&td_quote_bytes)?;

    // 8b. C2: Verify TDX quote ECDSA P-256 signature
    crate::platforms::tdx::verify::verify_quote_signature(&td_quote_bytes, &tdx_quote)?;

    // 9. HCL var_data binding: td_quote.report_data[..32] == SHA-256(null-trimmed var_data)
    // M1: Fix error message — this uses SHA-256, not SHA-384
    let var_data_hash = crate::utils::sha256(&hcl.var_data);
    let hcl_binding_valid =
        crate::utils::constant_time_eq(&tdx_quote.body.report_data[..32], &var_data_hash);

    if !hcl_binding_valid {
        return Err(AttestationError::SignatureVerificationFailed(
            "HCL var_data binding failed: TDX quote report_data != SHA-256(var_data)".to_string(),
        ));
    }

    // 10. Init data check: expected_init_data_hash vs PCR[8] (H2: enforce match)
    let init_data_match = if let Some(expected) = &params.expected_init_data_hash {
        if tpm_pcrs.len() > 8 {
            let mut padded = vec![0u8; 32];
            let len = expected.len().min(32);
            padded[..len].copy_from_slice(&expected[..len]);
            if !crate::utils::constant_time_eq(&tpm_pcrs[8], &padded) {
                return Err(AttestationError::InitDataMismatch);
            }
            Some(true)
        } else {
            return Err(AttestationError::InitDataMismatch);
        }
    } else {
        None
    };

    // 11. Extract TDX claims + TPM PCR values
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
            td_quote: BASE64URL.encode([0u8; 100]),
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
        // Build a properly-formatted HCL report
        let tee_report_end = 0x20 + 1184;
        let content_start = tee_report_end + 20;
        let content = b"{}";
        let mut hcl = vec![0u8; content_start + content.len()];
        hcl[0..4].copy_from_slice(b"HCLA");
        let total_remaining = (20 + content.len()) as u32;
        hcl[tee_report_end..tee_report_end + 4].copy_from_slice(&total_remaining.to_le_bytes());
        hcl[tee_report_end + 4..tee_report_end + 8].copy_from_slice(&1u32.to_le_bytes());
        hcl[tee_report_end + 8..tee_report_end + 12]
            .copy_from_slice(&tpm_common::HCL_REPORT_TYPE_TDX.to_le_bytes());
        hcl[tee_report_end + 12..tee_report_end + 16].copy_from_slice(&1u32.to_le_bytes());
        hcl[tee_report_end + 16..tee_report_end + 20]
            .copy_from_slice(&(content.len() as u32).to_le_bytes());
        hcl[content_start..].copy_from_slice(content);

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
    fn test_hcl_var_data_binding_sha256() {
        // Azure TDX uses SHA-256 for HCL var_data binding (same as SNP)
        // The CoCo reference compares SHA-256(var_data) with td_quote.report_data[..32]
        let var_data = b"test variable data for tdx binding";
        let var_data_hash = crate::utils::sha256(var_data);

        assert_eq!(var_data_hash.len(), 32);
    }

    #[test]
    fn test_hcl_report_layout_consistent() {
        // Azure TDX uses the same HCL report layout as Azure SNP
        // TEE report at 0x20 (1184 bytes), var_data header at 0x4C0,
        // var_data content at 0x4D4
        assert_eq!(0x20 + 1184, 0x4C0);
        assert_eq!(0x4C0 + 20, 0x4D4);
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

    // --- Tests using real CoCo TDX HCL report fixture ---

    const COCO_TDX_HCL_REPORT: &[u8] = include_bytes!("../../../test_data/az_tdx/hcl-report.bin");

    #[test]
    fn test_coco_tdx_hcl_report_parses() {
        let parsed = tpm_common::parse_hcl_report(COCO_TDX_HCL_REPORT);
        assert!(parsed.is_ok(), "TDX HCL report should parse: {:?}", parsed.err());

        let parsed = parsed.unwrap();
        assert_eq!(parsed.tee_report.len(), 1184);
        assert_eq!(parsed.report_type, tpm_common::HCL_REPORT_TYPE_TDX);
        assert!(!parsed.var_data.is_empty());
    }

    #[test]
    fn test_coco_tdx_hcl_var_data_is_jwk_json() {
        let parsed = tpm_common::parse_hcl_report(COCO_TDX_HCL_REPORT).unwrap();

        let json: serde_json::Value = serde_json::from_slice(&parsed.var_data)
            .expect("TDX var_data should be valid JSON");
        assert!(json["keys"].is_array(), "JSON should contain 'keys' array");

        let keys = json["keys"].as_array().unwrap();
        let ak_key = keys.iter().find(|k| k["kid"] == "HCLAkPub");
        assert!(ak_key.is_some(), "should contain HCLAkPub key");
        assert_eq!(ak_key.unwrap()["kty"], "RSA");
    }

    #[test]
    fn test_coco_tdx_hcl_var_data_contains_ak_pub() {
        let parsed = tpm_common::parse_hcl_report(COCO_TDX_HCL_REPORT).unwrap();

        let result = tpm_common::extract_ak_pub_from_jwk_json(&parsed.var_data);
        assert!(
            result.is_ok(),
            "should extract AK pub from TDX JWK JSON: {:?}",
            result.err()
        );

        let (modulus, exponent) = result.unwrap();
        assert_eq!(modulus.len(), 256, "RSA 2048 modulus should be 256 bytes");
        assert_eq!(exponent, vec![0x01, 0x00, 0x01], "exponent should be 65537");
    }

    #[test]
    fn test_coco_tdx_tpm_quote_v1_deserializes() {
        let json = include_str!("../../../test_data/az_tdx/tpm-quote-v1.json");
        let quote: std::result::Result<tpm_common::TpmQuote, _> = serde_json::from_str(json);
        assert!(
            quote.is_ok(),
            "tpm-quote-v1.json should deserialize: {:?}",
            quote.err()
        );

        let quote = quote.unwrap();
        assert_eq!(quote.pcrs.len(), 24);
        assert!(!quote.signature.is_empty());
        assert!(!quote.message.is_empty());
    }

    #[test]
    fn test_coco_tdx_evidence_v1_deserializes() {
        let json = include_str!("../../../test_data/az_tdx/evidence-v1.json");
        let envelope: crate::types::AttestationEvidence = serde_json::from_str(json).unwrap();
        assert_eq!(envelope.platform, crate::types::PlatformType::AzTdx);
        let evidence: std::result::Result<AzTdxEvidence, _> =
            serde_json::from_value(envelope.evidence);
        assert!(
            evidence.is_ok(),
            "TDX evidence-v1.json should deserialize: {:?}",
            evidence.err()
        );

        let evidence = evidence.unwrap();
        assert_eq!(evidence.version, 1);
        assert!(!evidence.hcl_report.is_empty());
        assert!(!evidence.td_quote.is_empty());
    }

    #[test]
    fn test_coco_tdx_tpm_signature_verification() {
        let parsed = tpm_common::parse_hcl_report(COCO_TDX_HCL_REPORT).unwrap();

        // Load TPM quote from JSON fixture
        let json = include_str!("../../../test_data/az_tdx/tpm-quote-v1.json");
        let quote: tpm_common::TpmQuote = serde_json::from_str(json).unwrap();

        let sig = hex::decode(&quote.signature).unwrap();
        let msg = hex::decode(&quote.message).unwrap();

        let result = tpm_common::verify_tpm_signature(&sig, &msg, &parsed.var_data);
        assert!(
            result.is_ok(),
            "TDX TPM signature should verify: {:?}",
            result.err()
        );
        assert!(result.unwrap(), "TPM signature should be valid");
    }
}
