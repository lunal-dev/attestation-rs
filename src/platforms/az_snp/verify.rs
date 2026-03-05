use crate::collateral::CertProvider;
use crate::error::{AttestationError, Result};
use crate::platforms::tpm_common;
use crate::types::{PlatformType, VerificationResult, VerifyParams};
use crate::utils::decode_base64url;

use super::evidence::AzSnpEvidence;

fn verify_hcl_var_data_binding(
    snp_report: &sev::firmware::guest::AttestationReport,
    var_data: &[u8],
) -> Result<()> {
    let hash = crate::utils::sha256(var_data);
    if !crate::utils::constant_time_eq(&snp_report.report_data[..32], &hash) {
        return Err(AttestationError::SignatureVerificationFailed(
            "HCL var_data binding failed: SNP report_data != SHA-256(var_data)".to_string(),
        ));
    }
    Ok(())
}

/// Verify Azure SNP vTPM attestation evidence.
pub async fn verify_evidence(
    evidence: &AzSnpEvidence,
    params: &VerifyParams,
    cert_provider: &dyn CertProvider,
) -> Result<VerificationResult> {
    if evidence.version != 1 {
        return Err(AttestationError::EvidenceDeserialize(format!(
            "unsupported az_snp evidence version: {}",
            evidence.version
        )));
    }

    // Input size validation
    crate::utils::check_field_size("hcl_report", evidence.hcl_report.len())?;
    crate::utils::check_field_size("vcek", evidence.vcek.len())?;
    crate::utils::check_field_size("tpm_quote.signature", evidence.tpm_quote.signature.len())?;
    crate::utils::check_field_size("tpm_quote.message", evidence.tpm_quote.message.len())?;

    // Decode
    let hcl_report_bytes = decode_base64url(&evidence.hcl_report)
        .map_err(|e| AttestationError::EvidenceDeserialize(format!("HCL report base64: {}", e)))?;
    let hcl = tpm_common::parse_hcl_report(&hcl_report_bytes)?;
    if hcl.report_type != tpm_common::HCL_REPORT_TYPE_SNP {
        return Err(AttestationError::QuoteParseFailed(format!(
            "HCL report_type is {} (expected {} for SNP)",
            hcl.report_type,
            tpm_common::HCL_REPORT_TYPE_SNP
        )));
    }
    let vcek_der = decode_base64url(&evidence.vcek)
        .map_err(|e| AttestationError::EvidenceDeserialize(format!("VCEK base64: {}", e)))?;
    let (tpm_sig, tpm_msg, tpm_pcrs) = tpm_common::decode_tpm_quote(&evidence.tpm_quote)?;
    let snp_report = crate::platforms::snp::verify::parse_report(&hcl.tee_report)?;

    // Version range check: Azure HCL may use v2 (no CPUID), up to MAX_REPORT_VERSION
    const AZ_MIN_REPORT_VERSION: u32 = 2;
    if snp_report.version < AZ_MIN_REPORT_VERSION
        || snp_report.version > crate::platforms::snp::verify::MAX_REPORT_VERSION
    {
        return Err(AttestationError::UnsupportedReportVersion {
            version: snp_report.version,
            min: AZ_MIN_REPORT_VERSION,
            max: crate::platforms::snp::verify::MAX_REPORT_VERSION,
        });
    }

    // TPM layer
    //
    // Verification order safety:
    // 1. TPM sig uses the AK (attestation key) extracted from var_data in the HCL
    //    report — an attacker cannot substitute a different AK without forging the
    //    TPM signature (RSA-2048 with the TPM's internal signing key).
    // 2. HCL binding then confirms var_data is bound to the TEE report via
    //    report_data[..32] == SHA-256(var_data).
    // 3. The TEE report itself is signed by the platform (VCEK/VLEK for SNP).
    // Trust chain: TEE report → var_data → AK → TPM quote → nonce
    tpm_common::verify_tpm_signature(&tpm_sig, &tpm_msg, &hcl.var_data)?;
    if params.expected_report_data.is_none() {
        log::warn!(
            "az-snp: no expected_report_data provided; TPM nonce binding will not be verified"
        );
    }
    let report_data_match =
        tpm_common::check_report_data(&tpm_msg, params.expected_report_data.as_deref())?;
    tpm_common::verify_tpm_pcrs(&tpm_msg, &tpm_pcrs)?;

    // HCL binding
    verify_hcl_var_data_binding(&snp_report, &hcl.var_data)?;

    // VCEK/VLEK validation against bundled AMD CA chain
    use crate::types::ProcessorGeneration;
    let is_vlek = crate::platforms::snp::verify::is_vlek_cert(&vcek_der)?;
    let cpuid_fam_id = snp_report.cpuid_fam_id.unwrap_or(0);
    let cpuid_mod_id = snp_report.cpuid_mod_id.unwrap_or(0);
    let processor_gen = ProcessorGeneration::from_cpuid(cpuid_fam_id, cpuid_mod_id);
    let gens = match processor_gen {
        Some(g) => vec![g],
        None => {
            log::warn!(
                "could not determine processor generation from CPUID \
                 (family=0x{:02X}, model=0x{:02X}); trying all known generations",
                cpuid_fam_id,
                cpuid_mod_id
            );
            vec![
                ProcessorGeneration::Milan,
                ProcessorGeneration::Genoa,
                ProcessorGeneration::Turin,
            ]
        }
    };
    let mut last_err = None;
    let mut matched_gen = None;
    for gen in &gens {
        let ark_der = crate::platforms::snp::certs::get_ark(*gen);
        // VLEK chain: ARK → ASVK → VLEK; VCEK chain: ARK → ASK → VCEK
        let intermediate_der = if is_vlek {
            crate::platforms::snp::certs::get_asvk(*gen)
        } else {
            crate::platforms::snp::certs::get_ask(*gen)
        };
        match crate::platforms::snp::verify::verify_cert_chain(ark_der, intermediate_der, &vcek_der)
        {
            Ok(()) => {
                matched_gen = Some(*gen);
                break;
            }
            Err(e) => {
                log::debug!("VEK chain check failed for {:?}: {}", gen, e);
                last_err = Some(e);
            }
        }
    }
    let matched_gen = matched_gen.ok_or_else(|| {
        last_err.unwrap_or_else(|| {
            AttestationError::CertChainError("no matching AMD root cert found".to_string())
        })
    })?;

    // CRL revocation check (if provider supplies CRL data)
    if let Some(crl_der) = cert_provider.get_snp_crl(matched_gen).await? {
        crate::platforms::snp::verify::check_vcek_not_revoked(&vcek_der, &crl_der)?;
    }

    // SNP report signature against VCEK
    crate::platforms::snp::verify::verify_report_signature(&hcl.tee_report, &vcek_der)?;

    // VMPL check
    if snp_report.vmpl != 0 {
        return Err(AttestationError::VmplCheckFailed(snp_report.vmpl));
    }

    // Debug policy enforcement
    if snp_report.policy.debug_allowed() && !params.allow_debug {
        return Err(AttestationError::DebugPolicyViolation);
    }

    // VCEK OID cross-validation
    crate::platforms::snp::verify::verify_vcek_tcb(&snp_report, &vcek_der)?;

    // Minimum TCB enforcement (including FMC for Turin)
    if let Some(ref min_tcb) = params.min_tcb {
        let tcb = &snp_report.reported_tcb;
        let fmc_below = match (min_tcb.fmc, tcb.fmc) {
            (Some(min_fmc), Some(report_fmc)) => report_fmc < min_fmc,
            (Some(_), None) => true, // min requires FMC but report doesn't have it
            _ => false,
        };
        if tcb.bootloader < min_tcb.bootloader
            || tcb.tee < min_tcb.tee
            || tcb.snp < min_tcb.snp
            || tcb.microcode < min_tcb.microcode
            || fmc_below
        {
            return Err(AttestationError::TcbMismatch(format!(
                "reported TCB ({}.{}.{}.{}) below minimum ({}.{}.{}.{})",
                tcb.bootloader,
                tcb.tee,
                tcb.snp,
                tcb.microcode,
                min_tcb.bootloader,
                min_tcb.tee,
                min_tcb.snp,
                min_tcb.microcode,
            )));
        }
    }

    // Init data and result
    let init_data_match =
        tpm_common::check_init_data(&tpm_pcrs, params.expected_init_data_hash.as_deref())?;
    let snp_claims = crate::platforms::snp::claims::extract_claims(&snp_report);
    Ok(tpm_common::build_tpm_verification_result(
        snp_claims,
        &tpm_pcrs,
        &tpm_msg,
        PlatformType::AzSnp,
        report_data_match,
        init_data_match,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platforms::tpm_common::TpmQuote;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL, Engine};

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

        hcl[tee_report_end..tee_report_end + 4].copy_from_slice(&total_remaining.to_le_bytes());
        hcl[tee_report_end + 4..tee_report_end + 8].copy_from_slice(&count.to_le_bytes());
        hcl[tee_report_end + 8..tee_report_end + 12].copy_from_slice(&report_type.to_le_bytes());
        hcl[tee_report_end + 12..tee_report_end + 16].copy_from_slice(&version.to_le_bytes());
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
        assert!(
            err.contains("base64") || err.contains("Base64"),
            "error: {}",
            err
        );
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
            extracted_report_data,
            &computed[..],
            "HCL var_data binding: report_data[..32] should equal SHA-256(var_data)"
        );
    }

    #[test]
    fn test_snp_report_version_check_constants() {
        // Verify the version range constants are correct
        const AZ_MIN_REPORT_VERSION: u32 = 2;
        assert!(AZ_MIN_REPORT_VERSION <= crate::platforms::snp::verify::MAX_REPORT_VERSION);
        assert_eq!(crate::platforms::snp::verify::MAX_REPORT_VERSION, 5);

        // Version 6 would be rejected
        assert!(6 > crate::platforms::snp::verify::MAX_REPORT_VERSION);
        // Version 1 would be rejected (below az min)
        assert!(1 < AZ_MIN_REPORT_VERSION);
        // Verify our CoCo fixture is within range
        let parsed = tpm_common::parse_hcl_report(COCO_HCL_REPORT).unwrap();
        let snp_report = crate::platforms::snp::verify::parse_report(&parsed.tee_report).unwrap();
        assert!(
            snp_report.version >= AZ_MIN_REPORT_VERSION
                && snp_report.version <= crate::platforms::snp::verify::MAX_REPORT_VERSION,
            "CoCo fixture version {} should be in range [{}, {}]",
            snp_report.version,
            AZ_MIN_REPORT_VERSION,
            crate::platforms::snp::verify::MAX_REPORT_VERSION
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
        assert!(
            parsed.is_ok(),
            "CoCo HCL report should parse: {:?}",
            parsed.err()
        );

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
        assert_eq!(
            report.unwrap().version,
            2,
            "CoCo fixture uses SNP report v2"
        );
    }

    #[test]
    fn test_coco_hcl_var_data_binding() {
        let parsed = tpm_common::parse_hcl_report(COCO_HCL_REPORT).unwrap();
        let snp_report = crate::platforms::snp::verify::parse_report(&parsed.tee_report).unwrap();

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
        let json: serde_json::Value =
            serde_json::from_slice(&parsed.var_data).expect("var_data should be valid JSON");
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
        let envelope: crate::types::AttestationEvidence = serde_json::from_str(json).unwrap();
        let evidence: AzSnpEvidence = serde_json::from_value(envelope.evidence).unwrap();

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
    }

    #[test]
    fn test_coco_tpm_message_has_valid_magic() {
        let json = include_str!("../../../test_data/az_snp/evidence-v1.json");
        let envelope: crate::types::AttestationEvidence = serde_json::from_str(json).unwrap();
        let evidence: AzSnpEvidence = serde_json::from_value(envelope.evidence).unwrap();
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
        let envelope: crate::types::AttestationEvidence = serde_json::from_str(json).unwrap();
        assert_eq!(envelope.platform, crate::types::PlatformType::AzSnp);
        let evidence: std::result::Result<AzSnpEvidence, _> =
            serde_json::from_value(envelope.evidence);
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
