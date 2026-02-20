use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL, Engine};

use crate::collateral::CertProvider;
use crate::error::{AttestationError, Result};
use crate::platforms::tpm_common;
use crate::types::{PlatformType, VerificationResult, VerifyParams};

use super::evidence::AzSnpEvidence;

/// Decode URL-safe base64, tolerating optional padding.
fn decode_base64url(input: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    BASE64URL.decode(input.trim_end_matches('='))
}

/// Verify Azure SNP vTPM attestation evidence.
pub async fn verify_evidence(
    evidence: &AzSnpEvidence,
    params: &VerifyParams,
    cert_provider: &dyn CertProvider,
) -> Result<VerificationResult> {
    // 1. Decode HCL report
    let hcl_report_bytes = decode_base64url(&evidence.hcl_report)
        .map_err(|e| AttestationError::EvidenceDeserialize(format!("HCL report base64: {}", e)))?;

    // 2. Parse HCL report structure (extracts TEE report + var_data JSON)
    let hcl = tpm_common::parse_hcl_report(&hcl_report_bytes)?;

    // 3. Decode VCEK
    let vcek_der = decode_base64url(&evidence.vcek)
        .map_err(|e| AttestationError::EvidenceDeserialize(format!("VCEK base64: {}", e)))?;

    // 4. Parse TPM quote
    let (tpm_sig, tpm_msg, tpm_pcrs) = tpm_common::decode_tpm_quote(&evidence.tpm_quote)?;

    // 5. Extract SNP report from HCL TEE report
    let snp_report = crate::platforms::snp::verify::parse_report(&hcl.tee_report)?;

    // 6. TPM signature verification (AK pub key extracted from var_data JWK JSON)
    let tpm_sig_valid = tpm_common::verify_tpm_signature(&tpm_sig, &tpm_msg, &hcl.var_data)?;

    // 7. TPM nonce check
    let tpm_nonce_match = if let Some(expected) = &params.expected_report_data {
        Some(tpm_common::verify_tpm_nonce(&tpm_msg, expected)?)
    } else {
        None
    };

    // 8. TPM PCR integrity
    tpm_common::verify_tpm_pcrs(&tpm_msg, &tpm_pcrs)?;

    // 9. HCL var_data binding: report_data[..32] == SHA-256(null-trimmed var_data)
    let var_data_hash = crate::utils::sha256(&hcl.var_data);
    let hcl_binding_valid =
        crate::utils::constant_time_eq(&snp_report.report_data[..32], &var_data_hash);

    if !hcl_binding_valid {
        return Err(AttestationError::SignatureVerificationFailed(
            "HCL var_data binding failed: SNP report_data != SHA-256(var_data)".to_string(),
        ));
    }

    // 10. VCEK validation against bundled AMD CA chain
    // Azure CVMs may have zeroed CPUID fields in the SNP report.
    // Try CPUID first, then try each processor generation's cert chain.
    let processor_gen = crate::types::ProcessorGeneration::from_cpuid(
        snp_report.cpuid_fam_id.unwrap_or(0),
        snp_report.cpuid_mod_id.unwrap_or(0),
    );

    let cert_chain_result = if let Some(gen) = processor_gen {
        // Known processor generation from CPUID
        let (ark_der, ask_der) = cert_provider.get_snp_cert_chain(gen).await?;
        crate::platforms::snp::verify::verify_cert_chain_pub(&ark_der, &ask_der, &vcek_der)
    } else {
        // CPUID fields zeroed (common on Azure CVMs) — try each generation
        use crate::types::ProcessorGeneration::*;
        let mut last_err = None;
        let mut ok = false;
        for gen in &[Milan, Genoa, Turin] {
            let (ark_der, ask_der) = cert_provider.get_snp_cert_chain(*gen).await?;
            match crate::platforms::snp::verify::verify_cert_chain_pub(
                &ark_der, &ask_der, &vcek_der,
            ) {
                Ok(()) => {
                    ok = true;
                    break;
                }
                Err(e) => last_err = Some(e),
            }
        }
        if ok {
            Ok(())
        } else {
            Err(last_err.unwrap_or_else(|| {
                AttestationError::CertChainError("no matching AMD root cert found".to_string())
            }))
        }
    };
    cert_chain_result?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platforms::tpm_common::TpmQuote;

    /// Build a properly-formatted HCL report with HCLA magic, embedded SNP report,
    /// var_data header, and JSON content.
    fn build_hcl_report(snp_report: &[u8], var_data_content: &[u8]) -> Vec<u8> {
        let tee_report_end = 0x20 + 1184; // 0x4C0
        let header_size = 20;
        let content_start = tee_report_end + header_size; // 0x4D4

        let mut hcl = vec![0u8; content_start + var_data_content.len()];

        // HCLA magic
        hcl[0..4].copy_from_slice(b"HCLA");

        // Embed SNP report at offset 0x20
        let copy_len = snp_report.len().min(1184);
        hcl[0x20..0x20 + copy_len].copy_from_slice(&snp_report[..copy_len]);

        // var_data header (5 × LE u32)
        let total_remaining = (header_size + var_data_content.len()) as u32;
        let count: u32 = 1;
        let report_type: u32 = tpm_common::HCL_REPORT_TYPE_SNP;
        let version: u32 = 1;
        let content_length = var_data_content.len() as u32;

        hcl[tee_report_end..tee_report_end + 4]
            .copy_from_slice(&total_remaining.to_le_bytes());
        hcl[tee_report_end + 4..tee_report_end + 8]
            .copy_from_slice(&count.to_le_bytes());
        hcl[tee_report_end + 8..tee_report_end + 12]
            .copy_from_slice(&report_type.to_le_bytes());
        hcl[tee_report_end + 12..tee_report_end + 16]
            .copy_from_slice(&version.to_le_bytes());
        hcl[tee_report_end + 16..tee_report_end + 20]
            .copy_from_slice(&content_length.to_le_bytes());

        // var_data content
        hcl[content_start..].copy_from_slice(var_data_content);

        hcl
    }

    fn build_dummy_tpm_quote() -> TpmQuote {
        TpmQuote {
            signature: "00".repeat(256),
            message: "ff544347".to_string() + &"00".repeat(100),
            pcrs: (0..24).map(|_| "00".repeat(32)).collect(),
        }
    }

    #[test]
    fn test_az_snp_evidence_serialization_roundtrip() {
        let evidence = AzSnpEvidence {
            version: 1,
            tpm_quote: build_dummy_tpm_quote(),
            hcl_report: "dGVzdA".to_string(), // "test" in URL-safe base64
            vcek: "AAAA".to_string(),
        };

        let json = serde_json::to_string(&evidence).unwrap();
        let deserialized: AzSnpEvidence = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.version, 1);
        assert_eq!(deserialized.hcl_report, evidence.hcl_report);
        assert_eq!(deserialized.vcek, evidence.vcek);
        assert_eq!(deserialized.tpm_quote.pcrs.len(), 24);
    }

    #[test]
    fn test_hcl_report_too_short() {
        let short_hcl = vec![0u8; 100]; // Way too short
        let evidence = AzSnpEvidence {
            version: 1,
            tpm_quote: build_dummy_tpm_quote(),
            hcl_report: BASE64URL.encode(&short_hcl),
            vcek: BASE64URL.encode([0u8; 100]),
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        let provider = crate::collateral::DefaultCertProvider::new();
        let params = VerifyParams::default();

        let result = rt.block_on(verify_evidence(&evidence, &params, &provider));
        assert!(result.is_err(), "short HCL report should fail");
        let err = format!("{:?}", result.err().unwrap());
        assert!(
            err.contains("too short"),
            "error should mention too short: {}",
            err
        );
    }

    #[test]
    fn test_hcl_report_layout_constants() {
        // Verify HCL report layout:
        // TEE report at 0x20, 1184 bytes, ends at 0x4C0
        // var_data header 20 bytes at 0x4C0
        // var_data content starts at 0x4D4
        assert_eq!(0x20 + 1184, 0x4C0);
        assert_eq!(0x4C0 + 20, 0x4D4);
    }

    #[test]
    fn test_invalid_base64_hcl_report() {
        let evidence = AzSnpEvidence {
            version: 1,
            tpm_quote: build_dummy_tpm_quote(),
            hcl_report: "!!!invalid_base64!!!".to_string(),
            vcek: BASE64URL.encode([0u8; 100]),
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        let provider = crate::collateral::DefaultCertProvider::new();
        let params = VerifyParams::default();

        let result = rt.block_on(verify_evidence(&evidence, &params, &provider));
        assert!(result.is_err());
        let err = format!("{:?}", result.err().unwrap());
        assert!(err.contains("base64") || err.contains("Base64"), "error: {}", err);
    }

    #[test]
    fn test_invalid_base64_vcek() {
        let hcl = build_hcl_report(&[0u8; 1184], b"{}");
        let evidence = AzSnpEvidence {
            version: 1,
            tpm_quote: build_dummy_tpm_quote(),
            hcl_report: BASE64URL.encode(&hcl),
            vcek: "!!!invalid!!!".to_string(),
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        let provider = crate::collateral::DefaultCertProvider::new();
        let params = VerifyParams::default();

        let result = rt.block_on(verify_evidence(&evidence, &params, &provider));
        assert!(result.is_err());
    }

    #[test]
    fn test_hcl_var_data_binding_sha256() {
        // Verify the binding mechanism: report_data[..32] should equal SHA-256(var_data)
        let var_data = b"test variable data for binding";
        let var_data_hash = crate::utils::sha256(var_data);

        assert_eq!(var_data_hash.len(), 32);

        // Build an SNP report with report_data matching SHA-256(var_data)
        let mut snp_report = vec![0u8; 1184];
        // report_data is at offset 0x50 (80) in the SNP report
        snp_report[0x50..0x50 + 32].copy_from_slice(&var_data_hash);

        let hcl = build_hcl_report(&snp_report, var_data);

        // Parse the HCL report and verify binding
        let parsed = tpm_common::parse_hcl_report(&hcl).unwrap();
        let computed = crate::utils::sha256(&parsed.var_data);

        // report_data from TEE report
        let extracted_report_data = &parsed.tee_report[0x50..0x50 + 32];

        assert_eq!(
            extracted_report_data, &computed[..],
            "HCL var_data binding: report_data[..32] should equal SHA-256(var_data)"
        );
    }

    #[test]
    fn test_platform_type_is_az_snp() {
        assert_eq!(
            format!("{}", PlatformType::AzSnp),
            "az-snp",
            "platform type should display as az-snp"
        );
    }

    // --- Tests using real CoCo HCL report fixture ---

    const COCO_HCL_REPORT: &[u8] = include_bytes!("../../../test_data/az_snp/hcl-report.bin");

    #[test]
    fn test_coco_hcl_report_parses() {
        let parsed = tpm_common::parse_hcl_report(COCO_HCL_REPORT);
        assert!(parsed.is_ok(), "CoCo HCL report should parse: {:?}", parsed.err());

        let parsed = parsed.unwrap();
        assert_eq!(parsed.tee_report.len(), 1184);
        assert_eq!(parsed.report_type, tpm_common::HCL_REPORT_TYPE_SNP);
        assert!(!parsed.var_data.is_empty(), "var_data should not be empty");
    }

    #[test]
    fn test_coco_hcl_snp_report_parses() {
        let parsed = tpm_common::parse_hcl_report(COCO_HCL_REPORT).unwrap();
        let report = crate::platforms::snp::verify::parse_report(&parsed.tee_report);
        assert!(
            report.is_ok(),
            "SNP report from CoCo HCL should parse: {:?}",
            report.err()
        );
        assert_eq!(report.unwrap().version, 2, "CoCo fixture uses SNP report v2");
    }

    #[test]
    fn test_coco_hcl_var_data_binding() {
        let parsed = tpm_common::parse_hcl_report(COCO_HCL_REPORT).unwrap();
        let snp_report =
            crate::platforms::snp::verify::parse_report(&parsed.tee_report).unwrap();

        let var_data_hash = crate::utils::sha256(&parsed.var_data);

        assert!(
            crate::utils::constant_time_eq(&snp_report.report_data[..32], &var_data_hash),
            "HCL var_data binding: report_data[..32] == SHA-256(null-trimmed var_data)"
        );
    }

    #[test]
    fn test_coco_hcl_var_data_is_jwk_json() {
        let parsed = tpm_common::parse_hcl_report(COCO_HCL_REPORT).unwrap();

        // var_data should be valid JSON with a "keys" array
        let json: serde_json::Value = serde_json::from_slice(&parsed.var_data)
            .expect("var_data should be valid JSON");
        assert!(json["keys"].is_array(), "JSON should contain 'keys' array");

        // Should contain an HCLAkPub RSA key
        let keys = json["keys"].as_array().unwrap();
        let ak_key = keys.iter().find(|k| k["kid"] == "HCLAkPub");
        assert!(ak_key.is_some(), "should contain HCLAkPub key");
        assert_eq!(ak_key.unwrap()["kty"], "RSA");
    }

    #[test]
    fn test_coco_hcl_var_data_contains_ak_pub() {
        let parsed = tpm_common::parse_hcl_report(COCO_HCL_REPORT).unwrap();

        let result = tpm_common::extract_ak_pub_from_jwk_json(&parsed.var_data);
        assert!(
            result.is_ok(),
            "should extract AK pub from JWK JSON: {:?}",
            result.err()
        );

        let (modulus, exponent) = result.unwrap();
        assert_eq!(modulus.len(), 256, "RSA 2048 modulus should be 256 bytes");
        assert_eq!(exponent, vec![0x01, 0x00, 0x01], "exponent should be 65537");
    }

    #[test]
    fn test_coco_tpm_signature_verification() {
        // Use evidence-v1.json which has matching TPM quote + HCL report
        let json = include_str!("../../../test_data/az_snp/evidence-v1.json");
        let evidence: AzSnpEvidence = serde_json::from_str(json).unwrap();

        let hcl_bytes = decode_base64url(&evidence.hcl_report).unwrap();
        let parsed = tpm_common::parse_hcl_report(&hcl_bytes).unwrap();

        let sig = hex::decode(&evidence.tpm_quote.signature).unwrap();
        let msg = hex::decode(&evidence.tpm_quote.message).unwrap();

        let result = tpm_common::verify_tpm_signature(&sig, &msg, &parsed.var_data);
        assert!(
            result.is_ok(),
            "CoCo TPM signature should verify: {:?}",
            result.err()
        );
        assert!(result.unwrap(), "TPM signature should be valid");
    }

    #[test]
    fn test_coco_tpm_message_has_valid_magic() {
        let json = include_str!("../../../test_data/az_snp/evidence-v1.json");
        let evidence: AzSnpEvidence = serde_json::from_str(json).unwrap();
        let msg = hex::decode(&evidence.tpm_quote.message).unwrap();

        assert!(msg.len() >= 4, "TPM message too short");
        let magic = u32::from_be_bytes(msg[0..4].try_into().unwrap());
        assert_eq!(
            magic, 0xFF544347,
            "TPM Attest magic should be 0xFF544347, got 0x{:08X}",
            magic
        );
    }

    #[test]
    fn test_coco_evidence_v1_deserializes() {
        let json = include_str!("../../../test_data/az_snp/evidence-v1.json");
        let evidence: std::result::Result<AzSnpEvidence, _> = serde_json::from_str(json);
        assert!(
            evidence.is_ok(),
            "CoCo evidence-v1.json should deserialize: {:?}",
            evidence.err()
        );

        let evidence = evidence.unwrap();
        assert_eq!(evidence.version, 1);
        assert_eq!(evidence.tpm_quote.pcrs.len(), 24);
        assert!(!evidence.hcl_report.is_empty());
        assert!(!evidence.vcek.is_empty());
    }
}
