use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

use sev::certs::snp::{Certificate, Chain, Verifiable};
use sev::firmware::guest::AttestationReport;

use crate::collateral::CertProvider;
use crate::error::{AttestationError, Result};
use crate::types::{PlatformType, ProcessorGeneration, SnpTcb, VerificationResult, VerifyParams};

use super::claims::extract_claims;
use super::evidence::SnpEvidence;

/// SNP Attestation Report version (must be >= 3 for cpuid fields).
const MIN_REPORT_VERSION: u32 = 3;

/// Verify SNP attestation evidence.
pub async fn verify_evidence(
    evidence: &SnpEvidence,
    params: &VerifyParams,
    cert_provider: &dyn CertProvider,
) -> Result<VerificationResult> {
    // 1. Decode the attestation report
    let report_bytes = BASE64
        .decode(&evidence.attestation_report)
        .map_err(|e| AttestationError::EvidenceDeserialize(format!("base64 decode: {}", e)))?;

    // 2. Parse with sev crate
    let report = AttestationReport::from_bytes(&report_bytes)
        .map_err(|e| AttestationError::QuoteParseFailed(format!("SNP report parse: {}", e)))?;

    // 3. Version check
    if report.version < MIN_REPORT_VERSION {
        return Err(AttestationError::UnsupportedReportVersion {
            version: report.version,
            min: MIN_REPORT_VERSION,
            max: u32::MAX,
        });
    }

    // 4. Determine processor generation
    let cpuid_fam = report.cpuid_fam_id.unwrap_or(0);
    let cpuid_mod = report.cpuid_mod_id.unwrap_or(0);
    let processor_gen = ProcessorGeneration::from_cpuid(cpuid_fam, cpuid_mod).ok_or_else(|| {
        AttestationError::QuoteParseFailed(format!(
            "unknown processor: family=0x{:02X}, model=0x{:02X}",
            cpuid_fam, cpuid_mod
        ))
    })?;

    // 5. Resolve VCEK cert
    let vcek_der = resolve_vcek(evidence, &report, processor_gen, cert_provider).await?;

    // 6. Build sev cert chain and verify (ARK -> ASK -> VCEK)
    let (ark_der, ask_der) = super::certs::get_bundled_certs(processor_gen);
    verify_cert_chain(ark_der, ask_der, &vcek_der)?;

    // 7. Verify report signature against VCEK
    let vek = Certificate::from_der(&vcek_der)
        .map_err(|e| AttestationError::CertChainError(format!("VCEK to sev Certificate: {}", e)))?;
    (&vek, &report)
        .verify()
        .map_err(|e| AttestationError::SignatureVerificationFailed(format!("{}", e)))?;

    // 8. VMPL check
    if report.vmpl != 0 {
        return Err(AttestationError::VmplCheckFailed(report.vmpl));
    }

    // 9. Check report_data binding
    let report_data_match = params.expected_report_data.as_ref().map(|expected| {
        let padded = crate::utils::pad_report_data(expected, 64).unwrap_or_default();
        crate::utils::constant_time_eq(&report.report_data[..], &padded)
    });

    // 10. Check init_data binding (host_data, 32 bytes)
    let init_data_match = params.expected_init_data_hash.as_ref().map(|expected| {
        let mut padded = vec![0u8; 32];
        let len = expected.len().min(32);
        padded[..len].copy_from_slice(&expected[..len]);
        crate::utils::constant_time_eq(&report.host_data[..], &padded)
    });

    // 11. Extract claims
    let claims = extract_claims(&report);

    Ok(VerificationResult {
        signature_valid: true,
        platform: PlatformType::Snp,
        claims,
        report_data_match,
        init_data_match,
    })
}

/// Resolve the VCEK certificate - either from evidence or from cert provider.
async fn resolve_vcek(
    evidence: &SnpEvidence,
    report: &AttestationReport,
    processor_gen: ProcessorGeneration,
    cert_provider: &dyn CertProvider,
) -> Result<Vec<u8>> {
    if let Some(chain) = &evidence.cert_chain {
        // VCEK provided in evidence
        let vcek = BASE64
            .decode(&chain.vcek)
            .map_err(|e| AttestationError::CertChainError(format!("VCEK base64: {}", e)))?;
        Ok(vcek)
    } else {
        // Fetch from cert provider using report's TCB
        let tcb = SnpTcb {
            bootloader: report.reported_tcb.bootloader,
            tee: report.reported_tcb.tee,
            snp: report.reported_tcb.snp,
            microcode: report.reported_tcb.microcode,
        };
        let mut chip_id = [0u8; 64];
        chip_id.copy_from_slice(&report.chip_id[..]);
        cert_provider
            .get_snp_vcek(processor_gen, &chip_id, &tcb)
            .await
    }
}

/// Verify the AMD certificate chain: ARK (self-signed) -> ASK -> VCEK.
/// Delegates to the sev crate's Verifiable trait.
pub fn verify_cert_chain(ark_der: &[u8], ask_der: &[u8], vcek_der: &[u8]) -> Result<()> {
    let chain = Chain::from_der(ark_der, ask_der, vcek_der)
        .map_err(|e| AttestationError::CertChainError(format!("chain parse: {}", e)))?;
    chain
        .verify()
        .map_err(|e| AttestationError::CertChainError(format!("chain verify: {}", e)))?;
    Ok(())
}

/// Public entry point for cert chain verification (used by Azure platforms).
pub fn verify_cert_chain_pub(ark_der: &[u8], ask_der: &[u8], vcek_der: &[u8]) -> Result<()> {
    verify_cert_chain(ark_der, ask_der, vcek_der)
}

/// Verify a report signature against a VCEK certificate.
/// Delegates to the sev crate's Verifiable trait.
pub fn verify_report_signature(report_bytes: &[u8], vcek_der: &[u8]) -> Result<()> {
    let report = AttestationReport::from_bytes(report_bytes)
        .map_err(|e| AttestationError::QuoteParseFailed(format!("SNP report parse: {}", e)))?;
    let vek = Certificate::from_der(vcek_der)
        .map_err(|e| AttestationError::CertChainError(format!("VCEK parse: {}", e)))?;
    (&vek, &report)
        .verify()
        .map_err(|e| AttestationError::SignatureVerificationFailed(format!("{}", e)))?;
    Ok(())
}

/// Parse an SNP attestation report from raw bytes using the sev crate.
pub fn parse_report(report_bytes: &[u8]) -> Result<AttestationReport> {
    AttestationReport::from_bytes(report_bytes)
        .map_err(|e| AttestationError::QuoteParseFailed(format!("SNP report parse: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Decode;

    // Load real test fixtures at compile time
    const TEST_REPORT: &[u8] = include_bytes!("../../../test_data/snp/test-report.bin");
    const TEST_VCEK: &[u8] = include_bytes!("../../../test_data/snp/test-vcek.der");

    // Live Genoa v5 fixtures captured from this machine
    const LIVE_REPORT_V5: &[u8] =
        include_bytes!("../../../test_data/snp/live-report-v5-genoa.bin");
    const LIVE_VCEK_GENOA: &[u8] =
        include_bytes!("../../../test_data/snp/live-vcek-genoa.der");
    const TEST_VLEK_REPORT: &[u8] = include_bytes!("../../../test_data/snp/test-vlek-report.bin");
    const TEST_VCEK_INVALID_LEGACY: &[u8] =
        include_bytes!("../../../test_data/snp/test-vcek-invalid-legacy.der");
    const TEST_VCEK_INVALID_NEW: &[u8] =
        include_bytes!("../../../test_data/snp/test-vcek-invalid-new.der");

    // Azure IMDS real certificates (Milan)
    const IMDS_VCEK: &[u8] = include_bytes!("../../../test_data/az_snp/imds-vcek.der");
    const IMDS_ASK: &[u8] = include_bytes!("../../../test_data/az_snp/imds-chain-0.der");
    const IMDS_ARK: &[u8] = include_bytes!("../../../test_data/az_snp/imds-chain-1.der");

    #[test]
    fn test_parse_report_sev_crate() {
        let report = parse_report(TEST_REPORT).expect("failed to parse report");
        assert_eq!(report.version, 2);
        assert_eq!(report.vmpl, 0);
        assert_eq!(report.sig_algo, 1);
        assert!(report.measurement.iter().any(|&b| b != 0));
        assert!(report.report_data.iter().any(|&b| b != 0));
        assert!(report.chip_id.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_parse_report_fields() {
        let report = parse_report(TEST_REPORT).expect("failed to parse report");
        assert_eq!(report.version, 2);
        assert_eq!(report.guest_svn, 4);
        assert_eq!(report.vmpl, 0);
        assert_eq!(report.sig_algo, 1);

        // Policy
        assert_eq!(report.policy.abi_minor(), 31);
        assert_eq!(report.policy.abi_major(), 0);
        assert!(report.policy.smt_allowed());
        assert!(!report.policy.migrate_ma_allowed());
        assert!(!report.policy.debug_allowed());
        assert!(!report.policy.single_socket_required());

        // Platform info
        assert!(report.plat_info.smt_enabled());
        assert!(!report.plat_info.tsme_enabled());

        // TCB
        assert_eq!(report.reported_tcb.bootloader, 3);
        assert_eq!(report.reported_tcb.tee, 0);
        assert_eq!(report.reported_tcb.snp, 8);
        assert_eq!(report.reported_tcb.microcode, 115);

        // Version 2 has no CPUID fields
        assert!(report.cpuid_fam_id.is_none() || report.cpuid_fam_id == Some(0));
        assert!(report.cpuid_mod_id.is_none() || report.cpuid_mod_id == Some(0));
    }

    #[test]
    fn test_parse_vlek_report() {
        let report = parse_report(TEST_VLEK_REPORT).expect("failed to parse VLEK report");
        assert_eq!(report.version, 3);
        assert_eq!(report.guest_svn, 0);
        assert_eq!(report.vmpl, 1);
        assert_eq!(report.sig_algo, 1);
        assert!(report.measurement.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_parse_report_too_short() {
        let data = vec![0u8; 100];
        assert!(parse_report(&data).is_err());
    }

    #[test]
    fn test_report_exact_size() {
        assert_eq!(TEST_REPORT.len(), 1184);
    }

    #[test]
    fn test_vlek_report_exact_size() {
        assert_eq!(TEST_VLEK_REPORT.len(), 1184);
    }

    // ---------------------------------------------------------------
    // Certificate chain tests
    // ---------------------------------------------------------------

    #[test]
    fn test_cert_chain_validation_milan() {
        let (ark_der, ask_der) = super::super::certs::get_bundled_certs(ProcessorGeneration::Milan);
        let result = verify_cert_chain(ark_der, ask_der, TEST_VCEK);
        assert!(
            result.is_ok(),
            "Milan cert chain should verify: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_cert_chain_wrong_generation_fails() {
        let (ark_der, ask_der) = super::super::certs::get_bundled_certs(ProcessorGeneration::Genoa);
        let result = verify_cert_chain(ark_der, ask_der, TEST_VCEK);
        assert!(result.is_err(), "wrong generation certs should fail");
    }

    #[test]
    fn test_cert_chain_invalid_vcek_legacy() {
        let (ark_der, ask_der) = super::super::certs::get_bundled_certs(ProcessorGeneration::Milan);
        let result = verify_cert_chain(ark_der, ask_der, TEST_VCEK_INVALID_LEGACY);
        assert!(result.is_err(), "invalid legacy VCEK should fail");
    }

    #[test]
    fn test_cert_chain_invalid_vcek_new() {
        let (ark_der, ask_der) = super::super::certs::get_bundled_certs(ProcessorGeneration::Milan);
        let result = verify_cert_chain(ark_der, ask_der, TEST_VCEK_INVALID_NEW);
        assert!(result.is_err(), "invalid new VCEK should fail");
    }

    #[test]
    fn test_cert_chain_ark_self_signed() {
        let (ark_der, _) = super::super::certs::get_bundled_certs(ProcessorGeneration::Milan);
        let ark = x509_cert::Certificate::from_der(ark_der).expect("ARK parse");
        assert_eq!(ark.tbs_certificate.issuer, ark.tbs_certificate.subject);
    }

    #[test]
    fn test_cert_chain_ask_issued_by_ark() {
        let (ark_der, ask_der) = super::super::certs::get_bundled_certs(ProcessorGeneration::Milan);
        let ark = x509_cert::Certificate::from_der(ark_der).expect("ARK parse");
        let ask = x509_cert::Certificate::from_der(ask_der).expect("ASK parse");
        assert_eq!(ask.tbs_certificate.issuer, ark.tbs_certificate.subject);
    }

    // ---------------------------------------------------------------
    // Report signature tests
    // ---------------------------------------------------------------

    #[test]
    fn test_report_signature_valid() {
        let result = verify_report_signature(TEST_REPORT, TEST_VCEK);
        assert!(
            result.is_ok(),
            "report signature should verify: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_report_tamper_detection() {
        let mut tampered = TEST_REPORT.to_vec();
        tampered[0x90] ^= 0xFF; // Flip byte in measurement
        let result = verify_report_signature(&tampered, TEST_VCEK);
        assert!(result.is_err(), "tampered report should fail sig check");
    }

    #[test]
    fn test_signature_tamper_detection() {
        let mut tampered = TEST_REPORT.to_vec();
        tampered[0x2A0] ^= 0xFF; // Flip byte in signature R
        let result = verify_report_signature(&tampered, TEST_VCEK);
        assert!(result.is_err(), "tampered signature should fail");
    }

    // ---------------------------------------------------------------
    // Azure IMDS real certificate tests
    // ---------------------------------------------------------------

    #[test]
    fn test_imds_vcek_parses() {
        let cert = x509_cert::Certificate::from_der(IMDS_VCEK).expect("IMDS VCEK parse");
        let subject = format!("{}", cert.tbs_certificate.subject);
        assert!(subject.contains("SEV-VCEK"));
    }

    #[test]
    fn test_imds_full_cert_chain() {
        let result = verify_cert_chain(IMDS_ARK, IMDS_ASK, IMDS_VCEK);
        assert!(
            result.is_ok(),
            "IMDS cert chain should verify: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_imds_bundled_certs_verify() {
        let (ark_der, ask_der) = super::super::certs::get_bundled_certs(ProcessorGeneration::Milan);
        let result = verify_cert_chain(ark_der, ask_der, IMDS_VCEK);
        assert!(
            result.is_ok(),
            "IMDS VCEK against bundled certs: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_imds_wrong_generation_fails() {
        let (ark_der, ask_der) = super::super::certs::get_bundled_certs(ProcessorGeneration::Genoa);
        let result = verify_cert_chain(ark_der, ask_der, IMDS_VCEK);
        assert!(result.is_err(), "IMDS VCEK should not verify with Genoa certs");
    }

    // ---------------------------------------------------------------
    // Live Genoa v5 tests
    // ---------------------------------------------------------------

    #[test]
    fn test_live_v5_report_parses() {
        assert_eq!(LIVE_REPORT_V5.len(), 1184);
        let report = parse_report(LIVE_REPORT_V5).expect("live v5 parse");
        assert_eq!(report.version, 5);
        assert_eq!(report.vmpl, 0);
        assert_eq!(report.sig_algo, 1);
        assert_eq!(report.cpuid_fam_id, Some(0x19));
        assert_eq!(report.cpuid_mod_id, Some(0xA0));
        let gen = ProcessorGeneration::from_cpuid(
            report.cpuid_fam_id.unwrap(),
            report.cpuid_mod_id.unwrap(),
        );
        assert_eq!(gen, Some(ProcessorGeneration::Genoa));
    }

    #[test]
    fn test_live_v5_vcek_parses() {
        let cert = x509_cert::Certificate::from_der(LIVE_VCEK_GENOA).expect("VCEK parse");
        let subject = format!("{}", cert.tbs_certificate.subject);
        assert!(subject.contains("SEV-VCEK"));
        let issuer = format!("{}", cert.tbs_certificate.issuer);
        assert!(issuer.contains("SEV-Genoa"));
    }

    #[test]
    fn test_live_v5_genoa_cert_chain() {
        let (ark_der, ask_der) = super::super::certs::get_bundled_certs(ProcessorGeneration::Genoa);
        let result = verify_cert_chain(ark_der, ask_der, LIVE_VCEK_GENOA);
        assert!(
            result.is_ok(),
            "Genoa cert chain should verify: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_live_v5_report_signature() {
        let result = verify_report_signature(LIVE_REPORT_V5, LIVE_VCEK_GENOA);
        assert!(
            result.is_ok(),
            "live v5 sig should verify: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_processor_generation_detection() {
        assert_eq!(
            ProcessorGeneration::from_cpuid(0x19, 0x01),
            Some(ProcessorGeneration::Milan)
        );
        assert_eq!(
            ProcessorGeneration::from_cpuid(0x19, 0x11),
            Some(ProcessorGeneration::Genoa)
        );
        assert_eq!(
            ProcessorGeneration::from_cpuid(0x19, 0xA0),
            Some(ProcessorGeneration::Genoa)
        );
        assert_eq!(
            ProcessorGeneration::from_cpuid(0x1A, 0x00),
            Some(ProcessorGeneration::Turin)
        );
        assert_eq!(ProcessorGeneration::from_cpuid(0xFF, 0x00), None);
    }
}
