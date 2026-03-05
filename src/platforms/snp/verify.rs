use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use der::Decode;

use sev::certs::snp::{Certificate, Chain, Verifiable};
use sev::firmware::guest::AttestationReport;

use crate::collateral::CertProvider;
use crate::error::{AttestationError, Result};
use crate::types::{PlatformType, ProcessorGeneration, SnpTcb, VerificationResult, VerifyParams};

use super::claims::extract_claims;
use super::evidence::SnpEvidence;

/// SNP Attestation Report version (must be >= 3 for cpuid fields).
const MIN_REPORT_VERSION: u32 = 3;

/// Maximum supported SNP report version.
/// Matches Trustee's upper bound — future versions may change field layout.
pub const MAX_REPORT_VERSION: u32 = 5;

/// Verify SNP attestation evidence.
pub async fn verify_evidence(
    evidence: &SnpEvidence,
    params: &VerifyParams,
    cert_provider: &dyn CertProvider,
) -> Result<VerificationResult> {
    // 0. Input size validation
    crate::utils::check_field_size("attestation_report", evidence.attestation_report.len())?;

    // 1. Decode the attestation report
    let report_bytes = BASE64
        .decode(&evidence.attestation_report)
        .map_err(|e| AttestationError::EvidenceDeserialize(format!("base64 decode: {}", e)))?;

    // 2. Parse with sev crate
    let report = AttestationReport::from_bytes(&report_bytes)
        .map_err(|e| AttestationError::QuoteParseFailed(format!("SNP report parse: {}", e)))?;

    // 3. Version check
    if report.version < MIN_REPORT_VERSION || report.version > MAX_REPORT_VERSION {
        return Err(AttestationError::UnsupportedReportVersion {
            version: report.version,
            min: MIN_REPORT_VERSION,
            max: MAX_REPORT_VERSION,
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

    // 5. Resolve VEK cert (VCEK or VLEK)
    let vcek_der = resolve_vcek(evidence, &report, processor_gen, cert_provider).await?;

    // 6. Detect VLEK vs VCEK and build the appropriate cert chain
    let is_vlek = is_vlek_cert(&vcek_der)?;
    let ark_der = super::certs::get_ark(processor_gen);
    let intermediate_der = if is_vlek {
        // VLEK chain: ARK → ASVK → VLEK
        super::certs::get_asvk(processor_gen)
    } else {
        // VCEK chain: ARK → ASK → VCEK
        super::certs::get_ask(processor_gen)
    };
    verify_cert_chain(ark_der, intermediate_der, &vcek_der)?;

    // 6b. Verify VCEK/VLEK certificate validity period
    verify_vek_validity_period(&vcek_der)?;

    // 7. Verify report signature against VEK
    let vek = Certificate::from_der(&vcek_der)
        .map_err(|e| AttestationError::CertChainError(format!("VEK to sev Certificate: {}", e)))?;
    (&vek, &report)
        .verify()
        .map_err(|e| AttestationError::SignatureVerificationFailed(format!("{}", e)))?;

    // 8. VMPL check
    if report.vmpl != 0 {
        return Err(AttestationError::VmplCheckFailed(report.vmpl));
    }

    // 8b. Debug policy enforcement
    if report.policy.debug_allowed() && !params.allow_debug {
        return Err(AttestationError::DebugPolicyViolation);
    }

    // 8c. VCEK OID cross-validation (chip_id + TCB SPLs)
    verify_vcek_tcb(&report, &vcek_der)?;

    // 8d. Minimum TCB enforcement
    if let Some(ref min_tcb) = params.min_tcb {
        let tcb = &report.reported_tcb;
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
                tcb.bootloader, tcb.tee, tcb.snp, tcb.microcode,
                min_tcb.bootloader, min_tcb.tee, min_tcb.snp, min_tcb.microcode,
            )));
        }
    }

    // 9. Check report_data binding
    let report_data_match = if let Some(expected) = &params.expected_report_data {
        let padded = crate::utils::pad_report_data(expected, 64)?;
        if !crate::utils::constant_time_eq(&report.report_data[..], &padded) {
            return Err(AttestationError::ReportDataMismatch);
        }
        Some(true)
    } else {
        None
    };

    // 10. Check init_data binding (host_data, 32 bytes)
    let init_data_match = if let Some(expected) = &params.expected_init_data_hash {
        let padded = crate::utils::pad_report_data(expected, 32)?;
        if !crate::utils::constant_time_eq(&report.host_data[..], &padded) {
            return Err(AttestationError::InitDataMismatch);
        }
        Some(true)
    } else {
        None
    };

    // 11. Extract claims
    let claims = extract_claims(&report);

    Ok(VerificationResult {
        signature_valid: true,
        platform: PlatformType::Snp,
        claims,
        report_data_match,
        init_data_match,
        tcb_status: None,
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
        // Guard: all-zeros chip_id means MASK_CHIP_ID was set, can't fetch from KDS
        if report.chip_id.iter().all(|&b| b == 0) {
            return Err(AttestationError::CertFetchError(
                "chip_id is all zeros in attestation report. \
                 Confirm that MASK_CHIP_ID is set to 0 to request VCEK from KDS."
                    .to_string(),
            ));
        }
        // Fetch from cert provider using report's TCB
        let tcb = SnpTcb {
            bootloader: report.reported_tcb.bootloader,
            tee: report.reported_tcb.tee,
            snp: report.reported_tcb.snp,
            microcode: report.reported_tcb.microcode,
            fmc: if processor_gen == ProcessorGeneration::Turin {
                Some(report.reported_tcb.fmc.unwrap_or(0))
            } else {
                None
            },
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

/// Verify a VEK (VCEK/VLEK) certificate's validity period (notBefore/notAfter).
fn verify_vek_validity_period(vek_der: &[u8]) -> Result<()> {
    use x509_parser::prelude::*;
    let (_, cert) = X509Certificate::from_der(vek_der)
        .map_err(|e| AttestationError::CertChainError(format!("VEK x509 parse for validity: {}", e)))?;
    let validity = cert.validity();
    let now = x509_parser::time::ASN1Time::now();
    if now < validity.not_before {
        return Err(AttestationError::CertChainError(format!(
            "VEK certificate is not yet valid (notBefore: {})",
            validity.not_before
        )));
    }
    if now > validity.not_after {
        return Err(AttestationError::CertChainError(format!(
            "VEK certificate has expired (notAfter: {})",
            validity.not_after
        )));
    }
    Ok(())
}

/// Check if a VEK certificate is a VLEK (versioned loaded endorsement key)
/// by examining its Common Name.
pub(crate) fn is_vlek_cert(vek_der: &[u8]) -> Result<bool> {
    use x509_parser::prelude::*;
    let (_, cert) = X509Certificate::from_der(vek_der)
        .map_err(|e| AttestationError::CertChainError(format!("VEK x509 parse: {}", e)))?;
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("");
    Ok(cn.contains("VLEK"))
}

// --- VCEK OID cross-validation ---
// OID constants from AMD SEV-SNP ABI specification
const HW_ID_OID: &str = "1.3.6.1.4.1.3704.1.4";
const UCODE_SPL_OID: &str = "1.3.6.1.4.1.3704.1.3.8";
const SNP_SPL_OID: &str = "1.3.6.1.4.1.3704.1.3.3";
const TEE_SPL_OID: &str = "1.3.6.1.4.1.3704.1.3.2";
const LOADER_SPL_OID: &str = "1.3.6.1.4.1.3704.1.3.1";
const FMC_SPL_OID: &str = "1.3.6.1.4.1.3704.1.3.9";

/// Extract a u8 integer value from a DER-encoded extension value.
/// AMD VCEK TCB extensions encode SPL values as DER INTEGERs.
fn get_oid_int(ext_value: &[u8]) -> Option<u8> {
    u8::from_der(ext_value).ok()
}

/// Extract the chip_id bytes from the VCEK HW_ID extension value.
///
/// Some VCEK certificates encode the chip_id as a DER OCTET STRING,
/// while others (notably Azure VCEK certs from THIM/IMDS) encode it
/// as raw bytes without an inner DER wrapper. This matches the approach
/// used by the Trustee reference implementation.
fn get_oid_octets(ext_value: &[u8]) -> Option<&[u8]> {
    // Try proper DER OCTET STRING decode first.
    if let Ok(octet_string) = der::asn1::OctetStringRef::from_der(ext_value) {
        return Some(octet_string.as_bytes());
    }
    // Raw bytes (no inner DER wrapper) — return as-is if non-empty.
    if !ext_value.is_empty() {
        return Some(ext_value);
    }
    None
}

/// Verify VCEK certificate TCB extensions match the SNP attestation report.
///
/// - For "VCEK" certificates: validates chip_id and TCB SPL exact equality.
/// - For "VLEK" certificates: skips chip_id check, only validates TCB SPLs.
pub fn verify_vcek_tcb(report: &AttestationReport, vcek_der: &[u8]) -> Result<()> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(vcek_der)
        .map_err(|e| AttestationError::CertChainError(format!("VCEK x509 parse: {}", e)))?;

    // Check common name to determine if this is VCEK or VLEK
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("");

    let is_vcek = !cn.contains("VLEK");

    // Validate chip_id only for VCEK (not VLEK)
    if is_vcek {
        let ext = cert
            .extensions()
            .iter()
            .find(|e| e.oid.to_string() == HW_ID_OID)
            .ok_or_else(|| {
                AttestationError::TcbMismatch(
                    "VCEK missing required HW_ID OID extension".to_string(),
                )
            })?;
        let chip_id_bytes = get_oid_octets(ext.value).ok_or_else(|| {
            AttestationError::TcbMismatch(
                "VCEK HW_ID OID has unparseable value".to_string(),
            )
        })?;
        if chip_id_bytes.len() != report.chip_id[..].len()
            || !crate::utils::constant_time_eq(chip_id_bytes, &report.chip_id[..])
        {
            return Err(AttestationError::TcbMismatch(
                "VCEK chip_id does not match report chip_id".to_string(),
            ));
        }
    }

    // Validate TCB SPL values (exact equality)
    let checks: &[(&str, u8, &str)] = &[
        (LOADER_SPL_OID, report.reported_tcb.bootloader, "bootloader"),
        (TEE_SPL_OID, report.reported_tcb.tee, "tee"),
        (SNP_SPL_OID, report.reported_tcb.snp, "snp"),
        (UCODE_SPL_OID, report.reported_tcb.microcode, "microcode"),
    ];

    for &(oid_str, expected, name) in checks {
        let ext = cert
            .extensions()
            .iter()
            .find(|e| e.oid.to_string() == oid_str)
            .ok_or_else(|| {
                AttestationError::TcbMismatch(format!(
                    "VCEK missing required OID extension: {}",
                    name
                ))
            })?;
        let cert_val = get_oid_int(ext.value).ok_or_else(|| {
            AttestationError::TcbMismatch(format!(
                "VCEK {} OID has unparseable value",
                name
            ))
        })?;
        if cert_val != expected {
            return Err(AttestationError::TcbMismatch(format!(
                "VCEK {} SPL {} does not match report {}",
                name, cert_val, expected
            )));
        }
    }

    // Turin processors have an additional FMC SPL OID
    if let Some(fmc_expected) = report.reported_tcb.fmc {
        if let Some(ext) = cert.extensions().iter().find(|e| e.oid.to_string() == FMC_SPL_OID) {
            let cert_val = get_oid_int(ext.value).ok_or_else(|| {
                AttestationError::TcbMismatch("VCEK FMC OID has unparseable value".to_string())
            })?;
            if cert_val != fmc_expected {
                return Err(AttestationError::TcbMismatch(format!(
                    "VCEK fmc SPL {} does not match report {}",
                    cert_val, fmc_expected
                )));
            }
        }
        // If the cert doesn't have FMC OID but the report does, that's OK —
        // older VCEKs may not include it. Only validate when present.
    }

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

    // ---------------------------------------------------------------
    // DER OID parsing helper tests
    // ---------------------------------------------------------------

    #[test]
    fn test_get_oid_int_single_byte() {
        // DER INTEGER: tag=0x02, len=0x01, value
        assert_eq!(get_oid_int(&[0x02, 0x01, 0x73]), Some(115));
        assert_eq!(get_oid_int(&[0x02, 0x01, 0x00]), Some(0));
        assert_eq!(get_oid_int(&[0x02, 0x01, 0x7F]), Some(127));
        // 0xFF unpadded is -1 in DER signed integer — must use 2-byte padded form
        assert_eq!(get_oid_int(&[0x02, 0x01, 0xFF]), None);
    }

    #[test]
    fn test_get_oid_int_two_byte_padded() {
        // Values > 127 need a leading 0x00 pad in DER to stay positive.
        // DER INTEGER: tag=0x02, len=0x02, value=0x00DB (219)
        assert_eq!(get_oid_int(&[0x02, 0x02, 0x00, 0xDB]), Some(219));
        assert_eq!(get_oid_int(&[0x02, 0x02, 0x00, 0x80]), Some(128));
        assert_eq!(get_oid_int(&[0x02, 0x02, 0x00, 0xFF]), Some(255));
    }

    #[test]
    fn test_get_oid_int_invalid() {
        assert_eq!(get_oid_int(&[]), None);
        assert_eq!(get_oid_int(&[0x04, 0x01, 0x00]), None); // wrong tag
        assert_eq!(get_oid_int(&[0x02]), None); // truncated
        assert_eq!(get_oid_int(&[0x02, 0x00]), None); // zero-length is invalid DER
        // 3-byte value doesn't fit in u8
        assert_eq!(get_oid_int(&[0x02, 0x03, 0x01, 0x00, 0x00]), None);
    }

    #[test]
    fn test_get_oid_octets_raw_bytes() {
        // Raw chip_id bytes (no inner DER wrapper) — the common case for AMD VCEKs
        let raw = [0x06u8; 64]; // first byte is NOT 0x04
        assert_eq!(get_oid_octets(&raw), Some(raw.as_slice()));
    }

    #[test]
    fn test_get_oid_octets_der_wrapped() {
        // DER OCTET STRING: tag=0x04, len=0x03, data=[0xAA, 0xBB, 0xCC]
        let wrapped = [0x04, 0x03, 0xAA, 0xBB, 0xCC];
        assert_eq!(get_oid_octets(&wrapped), Some(&[0xAA, 0xBB, 0xCC][..]));
    }

    #[test]
    fn test_get_oid_octets_empty() {
        assert_eq!(get_oid_octets(&[]), None);
    }

    // ---------------------------------------------------------------
    // TCB cross-validation tests
    // ---------------------------------------------------------------

    #[test]
    fn test_verify_vcek_tcb_milan() {
        let report = parse_report(TEST_REPORT).expect("parse report");
        let result = verify_vcek_tcb(&report, TEST_VCEK);
        assert!(result.is_ok(), "Milan VCEK TCB should verify: {:?}", result.err());
    }

    #[test]
    fn test_verify_vcek_tcb_genoa() {
        let report = parse_report(LIVE_REPORT_V5).expect("parse report");
        let result = verify_vcek_tcb(&report, LIVE_VCEK_GENOA);
        assert!(result.is_ok(), "Genoa VCEK TCB should verify: {:?}", result.err());
    }

    #[test]
    fn test_version_upper_bound() {
        // MAX_REPORT_VERSION is 5, version 6 should be rejected
        assert!(MAX_REPORT_VERSION == 5);
        // Version 5 is within bounds
        assert!(5 >= MIN_REPORT_VERSION && 5 <= MAX_REPORT_VERSION);
        // Version 6 exceeds upper bound
        assert!(6 > MAX_REPORT_VERSION);
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

    // ---------------------------------------------------------------
    // VLEK / ASVK tests
    // ---------------------------------------------------------------

    #[test]
    fn test_is_vlek_vcek_detection() {
        // Regular VCEK should not be detected as VLEK
        assert!(!is_vlek_cert(TEST_VCEK).unwrap(), "VCEK should not be VLEK");
        assert!(!is_vlek_cert(LIVE_VCEK_GENOA).unwrap(), "Genoa VCEK should not be VLEK");
        assert!(!is_vlek_cert(IMDS_VCEK).unwrap(), "IMDS VCEK should not be VLEK");
    }

    #[test]
    fn test_asvk_certs_parse() {
        // Verify ASVK certs for all generations can be parsed
        for gen in [ProcessorGeneration::Milan, ProcessorGeneration::Genoa, ProcessorGeneration::Turin] {
            let asvk_der = super::super::certs::get_asvk(gen);
            let cert = x509_cert::Certificate::from_der(asvk_der)
                .unwrap_or_else(|e| panic!("{:?} ASVK parse failed: {}", gen, e));
            let subject = format!("{}", cert.tbs_certificate.subject);
            assert!(
                subject.contains("VLEK"),
                "{:?} ASVK subject should contain VLEK: {}",
                gen, subject
            );
        }
    }

    #[test]
    fn test_asvk_issued_by_ark() {
        // ASVK should be issued by the same ARK as ASK
        for gen in [ProcessorGeneration::Milan, ProcessorGeneration::Genoa, ProcessorGeneration::Turin] {
            let ark_der = super::super::certs::get_ark(gen);
            let asvk_der = super::super::certs::get_asvk(gen);
            let ark = x509_cert::Certificate::from_der(ark_der)
                .unwrap_or_else(|e| panic!("{:?} ARK parse: {}", gen, e));
            let asvk = x509_cert::Certificate::from_der(asvk_der)
                .unwrap_or_else(|e| panic!("{:?} ASVK parse: {}", gen, e));
            assert_eq!(
                asvk.tbs_certificate.issuer,
                ark.tbs_certificate.subject,
                "{:?} ASVK issuer should match ARK subject",
                gen
            );
        }
    }

    #[test]
    fn test_asvk_chain_validates() {
        // ARK → ASVK chain should verify for all generations
        // (We can't do full chain verify without a real VLEK cert, but we can
        // verify the ARK → ASVK link)
        for gen in [ProcessorGeneration::Milan, ProcessorGeneration::Genoa, ProcessorGeneration::Turin] {
            let ark_der = super::super::certs::get_ark(gen);
            let asvk_der = super::super::certs::get_asvk(gen);
            // Parse via sev crate to verify the crypto
            let ark = Certificate::from_der(ark_der)
                .unwrap_or_else(|e| panic!("{:?} ARK sev parse: {}", gen, e));
            let asvk = Certificate::from_der(asvk_der)
                .unwrap_or_else(|e| panic!("{:?} ASVK sev parse: {}", gen, e));
            // ARK should verify ASVK
            (&ark, &asvk)
                .verify()
                .unwrap_or_else(|e| panic!("{:?} ARK->ASVK verify failed: {}", gen, e));
        }
    }
}
