use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use der::Decode;

use crate::collateral::CertProvider;
use crate::error::{AttestationError, Result};
use crate::types::{PlatformType, ProcessorGeneration, SnpTcb, VerificationResult, VerifyParams};

use super::claims::extract_claims;
use super::evidence::SnpEvidence;

/// SNP Attestation Report version (must be >= 3 for cpuid fields).
const MIN_REPORT_VERSION: u32 = 3;

/// Parsed SNP attestation report (1184 bytes).
/// Field offsets based on AMD SEV-SNP ABI spec (Table 21).
#[derive(Debug, Clone)]
pub struct SnpReport {
    pub version: u32,
    pub guest_svn: u32,
    pub policy: u64,
    // Policy flags (parsed from policy field)
    pub policy_abi_major: u8,
    pub policy_abi_minor: u8,
    pub policy_smt_allowed: bool,
    pub policy_migrate_ma: bool,
    pub policy_debug_allowed: bool,
    pub policy_single_socket: bool,
    // Family/model for processor generation detection
    pub family_id: [u8; 16],
    pub image_id: [u8; 16],
    pub vmpl: u32,
    pub signature_algo: u32,
    pub current_tcb: u64,
    // Platform info
    pub platform_info: u64,
    pub plat_smt_enabled: bool,
    pub plat_tsme_enabled: bool,
    // Author key
    pub author_key_en: u32,
    // Report data and measurements
    pub report_data: [u8; 64],
    pub measurement: [u8; 48],
    pub host_data: [u8; 32],
    pub id_key_digest: [u8; 48],
    pub author_key_digest: [u8; 48],
    pub report_id: [u8; 32],
    pub report_id_ma: [u8; 32],
    // TCB
    pub reported_tcb: u64,
    pub reported_tcb_bootloader: u8,
    pub reported_tcb_tee: u8,
    pub reported_tcb_snp: u8,
    pub reported_tcb_microcode: u8,
    // CPU ID
    pub chip_id: [u8; 64],
    pub committed_tcb: u64,
    // Version fields
    pub current_build: u8,
    pub current_minor: u8,
    pub current_major: u8,
    pub committed_build: u8,
    pub committed_minor: u8,
    pub committed_major: u8,
    // Launch TCB
    pub launch_tcb: u64,
    // CPUID family/model (report version >= 3)
    pub cpuid_fam_id: u8,
    pub cpuid_mod_id: u8,
    pub cpuid_stepping: u8,
    // Signature (ECDSA P-384: r (72 bytes) + s (72 bytes))
    pub signature_r: [u8; 72],
    pub signature_s: [u8; 72],
}

impl SnpReport {
    /// Parse an SNP attestation report from raw bytes.
    /// The report is 1184 bytes in the standard format.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 1184 {
            return Err(AttestationError::QuoteParseFailed(format!(
                "SNP report too short: {} bytes, expected 1184",
                data.len()
            )));
        }

        let version = u32::from_le_bytes(data[0x00..0x04].try_into().unwrap());
        let guest_svn = u32::from_le_bytes(data[0x04..0x08].try_into().unwrap());
        let policy = u64::from_le_bytes(data[0x08..0x10].try_into().unwrap());

        // Parse policy flags
        let policy_abi_minor = (policy & 0xFF) as u8;
        let policy_abi_major = ((policy >> 8) & 0xFF) as u8;
        let policy_smt_allowed = (policy >> 16) & 1 == 1;
        let policy_migrate_ma = (policy >> 18) & 1 == 1;
        let policy_debug_allowed = (policy >> 19) & 1 == 1;
        let policy_single_socket = (policy >> 20) & 1 == 1;

        let mut family_id = [0u8; 16];
        family_id.copy_from_slice(&data[0x10..0x20]);

        let mut image_id = [0u8; 16];
        image_id.copy_from_slice(&data[0x20..0x30]);

        let vmpl = u32::from_le_bytes(data[0x30..0x34].try_into().unwrap());
        let signature_algo = u32::from_le_bytes(data[0x34..0x38].try_into().unwrap());
        let current_tcb = u64::from_le_bytes(data[0x38..0x40].try_into().unwrap());

        let platform_info = u64::from_le_bytes(data[0x40..0x48].try_into().unwrap());
        let plat_smt_enabled = platform_info & 1 == 1;
        let plat_tsme_enabled = (platform_info >> 1) & 1 == 1;

        let author_key_en = u32::from_le_bytes(data[0x48..0x4C].try_into().unwrap());

        // 0x4C..0x50 reserved

        let mut report_data = [0u8; 64];
        report_data.copy_from_slice(&data[0x50..0x90]);

        let mut measurement = [0u8; 48];
        measurement.copy_from_slice(&data[0x90..0xC0]);

        let mut host_data = [0u8; 32];
        host_data.copy_from_slice(&data[0xC0..0xE0]);

        let mut id_key_digest = [0u8; 48];
        id_key_digest.copy_from_slice(&data[0xE0..0x110]);

        let mut author_key_digest = [0u8; 48];
        author_key_digest.copy_from_slice(&data[0x110..0x140]);

        let mut report_id = [0u8; 32];
        report_id.copy_from_slice(&data[0x140..0x160]);

        let mut report_id_ma = [0u8; 32];
        report_id_ma.copy_from_slice(&data[0x160..0x180]);

        let reported_tcb = u64::from_le_bytes(data[0x180..0x188].try_into().unwrap());
        let reported_tcb_bootloader = data[0x180];
        let reported_tcb_tee = data[0x181];
        // bytes 0x182..0x184 are reserved
        let reported_tcb_snp = data[0x184];
        // bytes 0x185..0x187 are reserved
        let reported_tcb_microcode = data[0x187];

        // 0x188..0x1A0 reserved

        let mut chip_id = [0u8; 64];
        chip_id.copy_from_slice(&data[0x1A0..0x1E0]);

        let committed_tcb = u64::from_le_bytes(data[0x1E0..0x1E8].try_into().unwrap());

        let current_build = data[0x1E8];
        let current_minor = data[0x1E9];
        let current_major = data[0x1EA];
        // 0x1EB reserved

        let committed_build = data[0x1EC];
        let committed_minor = data[0x1ED];
        let committed_major = data[0x1EE];
        // 0x1EF reserved

        let launch_tcb = u64::from_le_bytes(data[0x1F0..0x1F8].try_into().unwrap());
        // CPUID fields at 0x188-0x18A (only valid in version >= 3)
        // Per AMD SEV-SNP ABI spec (56860 Rev 1.58), Table 23
        let cpuid_fam_id = if version >= 3 { data[0x188] } else { 0 };
        let cpuid_mod_id = if version >= 3 { data[0x189] } else { 0 };
        let cpuid_stepping = if version >= 3 { data[0x18A] } else { 0 };
        // Signature at offset 0x2A0 (672)
        let sig_offset = 0x2A0;
        let mut signature_r = [0u8; 72];
        signature_r.copy_from_slice(&data[sig_offset..sig_offset + 72]);
        let mut signature_s = [0u8; 72];
        signature_s.copy_from_slice(&data[sig_offset + 72..sig_offset + 144]);

        Ok(Self {
            version,
            guest_svn,
            policy,
            policy_abi_major,
            policy_abi_minor,
            policy_smt_allowed,
            policy_migrate_ma,
            policy_debug_allowed,
            policy_single_socket,
            family_id,
            image_id,
            vmpl,
            signature_algo,
            current_tcb,
            platform_info,
            plat_smt_enabled,
            plat_tsme_enabled,
            author_key_en,
            report_data,
            measurement,
            host_data,
            id_key_digest,
            author_key_digest,
            report_id,
            report_id_ma,
            reported_tcb,
            reported_tcb_bootloader,
            reported_tcb_tee,
            reported_tcb_snp,
            reported_tcb_microcode,
            chip_id,
            committed_tcb,
            current_build,
            current_minor,
            current_major,
            committed_build,
            committed_minor,
            committed_major,
            launch_tcb,
            cpuid_fam_id,
            cpuid_mod_id,
            cpuid_stepping,
            signature_r,
            signature_s,
        })
    }
}

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

    let report = SnpReport::from_bytes(&report_bytes)?;

    // 2. Version check
    if report.version < MIN_REPORT_VERSION {
        return Err(AttestationError::UnsupportedReportVersion {
            version: report.version,
            min: MIN_REPORT_VERSION,
            max: u32::MAX,
        });
    }

    // 3. Determine processor generation
    let processor_gen = ProcessorGeneration::from_cpuid(report.cpuid_fam_id, report.cpuid_mod_id)
        .ok_or_else(|| {
        AttestationError::QuoteParseFailed(format!(
            "unknown processor: family=0x{:02X}, model=0x{:02X}",
            report.cpuid_fam_id, report.cpuid_mod_id
        ))
    })?;

    // 4. Resolve VCEK cert
    let vcek_der = resolve_vcek(evidence, &report, processor_gen, cert_provider).await?;

    // 5. Get the bundled ARK and ASK
    let (ark_der, ask_der) = super::certs::get_bundled_certs(processor_gen);

    // 6. Verify certificate chain: ARK (self-signed) -> ASK -> VCEK
    verify_cert_chain(ark_der, ask_der, &vcek_der)?;

    // 7. Verify report signature against VCEK
    let sig_valid = verify_report_signature(&report_bytes, &vcek_der)?;

    // 8. VMPL check
    if report.vmpl != 0 {
        return Err(AttestationError::VmplCheckFailed(report.vmpl));
    }

    // 9. Check report_data binding
    let report_data_match = params.expected_report_data.as_ref().map(|expected| {
        let padded = crate::utils::pad_report_data(expected, 64).unwrap_or_default();
        crate::utils::constant_time_eq(&report.report_data, &padded)
    });

    // 10. Check init_data binding (host_data, 32 bytes)
    let init_data_match = params.expected_init_data_hash.as_ref().map(|expected| {
        let mut padded = vec![0u8; 32];
        let len = expected.len().min(32);
        padded[..len].copy_from_slice(&expected[..len]);
        crate::utils::constant_time_eq(&report.host_data, &padded)
    });

    // 11. Extract claims
    let claims = extract_claims(&report);

    Ok(VerificationResult {
        signature_valid: sig_valid,
        platform: PlatformType::Snp,
        claims,
        report_data_match,
        init_data_match,
    })
}

/// Resolve the VCEK certificate - either from evidence or from cert provider.
async fn resolve_vcek(
    evidence: &SnpEvidence,
    report: &SnpReport,
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
        // Fetch from cert provider
        let tcb = SnpTcb {
            bootloader: report.reported_tcb_bootloader,
            tee: report.reported_tcb_tee,
            snp: report.reported_tcb_snp,
            microcode: report.reported_tcb_microcode,
        };
        cert_provider
            .get_snp_vcek(processor_gen, &report.chip_id, &tcb)
            .await
    }
}

/// Public entry point for cert chain verification (used by Azure platforms).
pub fn verify_cert_chain_pub(ark_der: &[u8], ask_der: &[u8], vcek_der: &[u8]) -> Result<()> {
    verify_cert_chain(ark_der, ask_der, vcek_der)
}

/// Public entry point for report signature verification (used by benchmarks).
pub fn verify_report_signature_pub(report_bytes: &[u8], vcek_der: &[u8]) -> Result<bool> {
    verify_report_signature(report_bytes, vcek_der)
}

/// Verify the AMD certificate chain: ARK (self-signed) -> ASK -> VCEK.
/// Uses pure-Rust crypto for WASM compatibility.
fn verify_cert_chain(ark_der: &[u8], ask_der: &[u8], vcek_der: &[u8]) -> Result<()> {
    // Parse certificates
    let ark_cert = x509_cert::Certificate::from_der(ark_der)
        .map_err(|e| AttestationError::CertChainError(format!("ARK parse: {}", e)))?;
    let ask_cert = x509_cert::Certificate::from_der(ask_der)
        .map_err(|e| AttestationError::CertChainError(format!("ASK parse: {}", e)))?;
    let vcek_cert = x509_cert::Certificate::from_der(vcek_der)
        .map_err(|e| AttestationError::CertChainError(format!("VCEK parse: {}", e)))?;

    // Verify ARK is self-signed (issuer == subject)
    if ark_cert.tbs_certificate.issuer != ark_cert.tbs_certificate.subject {
        return Err(AttestationError::CertChainError(
            "ARK is not self-signed".to_string(),
        ));
    }

    // Verify ARK signature on itself
    verify_cert_signature(&ark_cert, &ark_cert)?;

    // Verify ARK signed ASK
    verify_cert_signature(&ark_cert, &ask_cert)?;

    // Verify ASK signed VCEK
    verify_cert_signature(&ask_cert, &vcek_cert)?;

    Ok(())
}

/// Verify that `issuer_cert` signed `subject_cert`.
/// Supports both ECDSA P-384 (Genoa/Turin) and RSA-PSS SHA-384 (Milan).
fn verify_cert_signature(
    issuer_cert: &x509_cert::Certificate,
    subject_cert: &x509_cert::Certificate,
) -> Result<()> {
    use der::Encode;

    // The TBS (to-be-signed) certificate bytes
    let tbs_bytes = subject_cert
        .tbs_certificate
        .to_der()
        .map_err(|e| AttestationError::CertChainError(format!("TBS encode: {}", e)))?;

    // The signature from the subject cert
    let sig_bytes = subject_cert.signature.raw_bytes();

    // Determine key type from the issuer's SubjectPublicKeyInfo algorithm OID
    let issuer_spki = &issuer_cert.tbs_certificate.subject_public_key_info;
    let algorithm_oid = &issuer_spki.algorithm.oid;

    // OID 1.2.840.113549.1.1.1 = rsaEncryption
    const RSA_OID: der::oid::ObjectIdentifier =
        der::oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
    // OID 1.2.840.10045.2.1 = id-ecPublicKey
    const EC_OID: der::oid::ObjectIdentifier =
        der::oid::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

    if *algorithm_oid == RSA_OID {
        verify_cert_signature_rsa_pss(
            issuer_spki.subject_public_key.raw_bytes(),
            &tbs_bytes,
            sig_bytes,
        )
    } else if *algorithm_oid == EC_OID {
        verify_cert_signature_ecdsa_p384(
            issuer_spki.subject_public_key.raw_bytes(),
            &tbs_bytes,
            sig_bytes,
        )
    } else {
        Err(AttestationError::CertChainError(format!(
            "unsupported issuer key algorithm OID: {}",
            algorithm_oid
        )))
    }
}

/// Verify an RSA-PSS SHA-384 signature (used by Milan ARK/ASK).
fn verify_cert_signature_rsa_pss(
    pub_key_bytes: &[u8],
    tbs_bytes: &[u8],
    sig_bytes: &[u8],
) -> Result<()> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::pss::{Signature, VerifyingKey};
    use signature::Verifier;

    // The BIT STRING content for RSA is a PKCS#1 RSAPublicKey DER encoding
    let public_key = rsa::RsaPublicKey::from_pkcs1_der(pub_key_bytes)
        .map_err(|e| AttestationError::CertChainError(format!("RSA pubkey parse: {}", e)))?;

    let verifying_key = VerifyingKey::<sha2::Sha384>::new(public_key);

    let signature = Signature::try_from(sig_bytes)
        .map_err(|e| AttestationError::CertChainError(format!("RSA-PSS sig parse: {}", e)))?;

    verifying_key
        .verify(tbs_bytes, &signature)
        .map_err(|e| AttestationError::CertChainError(format!("RSA-PSS verify: {}", e)))?;

    Ok(())
}

/// Verify an ECDSA P-384 signature (used by Genoa/Turin ARK/ASK).
fn verify_cert_signature_ecdsa_p384(
    pub_key_bytes: &[u8],
    tbs_bytes: &[u8],
    sig_bytes: &[u8],
) -> Result<()> {
    use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    let verifying_key = VerifyingKey::from_sec1_bytes(pub_key_bytes)
        .map_err(|e| AttestationError::CertChainError(format!("EC pubkey parse: {}", e)))?;

    let signature = Signature::from_der(sig_bytes)
        .map_err(|e| AttestationError::CertChainError(format!("ECDSA sig parse: {}", e)))?;

    verifying_key
        .verify(tbs_bytes, &signature)
        .map_err(|e| AttestationError::CertChainError(format!("ECDSA verify: {}", e)))?;

    Ok(())
}

/// Verify the attestation report ECDSA P-384 signature against the VCEK public key.
/// The signature covers bytes 0x00..0x2A0 of the report.
fn verify_report_signature(report_bytes: &[u8], vcek_der: &[u8]) -> Result<bool> {
    use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    // Parse VCEK to get public key
    let vcek_cert = x509_cert::Certificate::from_der(vcek_der)
        .map_err(|e| AttestationError::CertChainError(format!("VCEK parse: {}", e)))?;

    let pub_key_bytes = vcek_cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();

    let verifying_key = VerifyingKey::from_sec1_bytes(pub_key_bytes).map_err(|e| {
        AttestationError::SignatureVerificationFailed(format!("VCEK pubkey: {}", e))
    })?;

    // The signed portion is bytes 0..0x2A0 (672 bytes)
    let signed_data = &report_bytes[..0x2A0];

    // The signature is at offset 0x2A0: R component (72 bytes) + S component (72 bytes)
    // These are unsigned little-endian integers in the report, need to convert to big-endian DER
    let sig_r = &report_bytes[0x2A0..0x2A0 + 48]; // Only first 48 bytes are meaningful for P-384
    let sig_s = &report_bytes[0x2A0 + 72..0x2A0 + 72 + 48];

    // Convert from little-endian to big-endian
    let mut r_be = [0u8; 48];
    let mut s_be = [0u8; 48];
    for i in 0..48 {
        r_be[i] = sig_r[47 - i];
        s_be[i] = sig_s[47 - i];
    }

    let signature =
        Signature::from_scalars(p384::FieldBytes::from(r_be), p384::FieldBytes::from(s_be))
            .map_err(|e| {
                AttestationError::SignatureVerificationFailed(format!("sig construct: {}", e))
            })?;

    match verifying_key.verify(signed_data, &signature) {
        Ok(()) => Ok(true),
        Err(e) => Err(AttestationError::SignatureVerificationFailed(format!(
            "ECDSA P-384: {}",
            e
        ))),
    }
}

/// Extract TCB values from VCEK certificate x509 extensions.
/// AMD TCB OIDs: 1.3.6.1.4.1.3704.1.3.{1..8}
#[allow(dead_code)]
fn extract_vcek_tcb(vcek_der: &[u8]) -> Result<SnpTcb> {
    let cert = x509_cert::Certificate::from_der(vcek_der)
        .map_err(|e| AttestationError::CertChainError(format!("VCEK parse: {}", e)))?;

    // OID prefix for AMD TCB extensions: 1.3.6.1.4.1.3704.1.3
    let _tcb_oid_prefix = "1.3.6.1.4.1.3704.1.3";

    // Extract from extensions - we need bootloader (OID .1), tee (.2), snp (.3), microcode (.8)
    let mut bootloader = 0u8;
    let mut tee = 0u8;
    let mut snp = 0u8;
    let mut microcode = 0u8;

    if let Some(extensions) = &cert.tbs_certificate.extensions {
        for ext in extensions.iter() {
            let oid_str = ext.extn_id.to_string();
            if let Some(suffix) = oid_str.strip_prefix("1.3.6.1.4.1.3704.1.3.") {
                let value = ext.extn_value.as_bytes();
                // The value is ASN.1 encoded integer
                let val = parse_asn1_integer(value).unwrap_or(0);
                match suffix {
                    "1" => bootloader = val as u8,
                    "2" => tee = val as u8,
                    "3" => snp = val as u8,
                    "8" => microcode = val as u8,
                    _ => {}
                }
            }
        }
    }

    Ok(SnpTcb {
        bootloader,
        tee,
        snp,
        microcode,
    })
}

/// Parse a simple ASN.1 INTEGER value.
fn parse_asn1_integer(data: &[u8]) -> Option<u64> {
    if data.len() < 3 || data[0] != 0x02 {
        return None;
    }
    let len = data[1] as usize;
    if data.len() < 2 + len {
        return None;
    }
    let bytes = &data[2..2 + len];
    let mut value = 0u64;
    for &b in bytes {
        value = (value << 8) | b as u64;
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Load real test fixtures at compile time
    const TEST_REPORT: &[u8] = include_bytes!("../../../test_data/snp/test-report.bin");
    const TEST_VCEK: &[u8] = include_bytes!("../../../test_data/snp/test-vcek.der");
    const TEST_VLEK: &[u8] = include_bytes!("../../../test_data/snp/test-vlek.der");
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
    fn test_processor_generation_detection() {
        // Milan
        assert_eq!(
            ProcessorGeneration::from_cpuid(0x19, 0x01),
            Some(ProcessorGeneration::Milan)
        );
        // Genoa
        assert_eq!(
            ProcessorGeneration::from_cpuid(0x19, 0x11),
            Some(ProcessorGeneration::Genoa)
        );
        assert_eq!(
            ProcessorGeneration::from_cpuid(0x19, 0xA0),
            Some(ProcessorGeneration::Genoa)
        );
        // Turin
        assert_eq!(
            ProcessorGeneration::from_cpuid(0x1A, 0x00),
            Some(ProcessorGeneration::Turin)
        );
        // Unknown
        assert_eq!(ProcessorGeneration::from_cpuid(0xFF, 0x00), None);
    }

    #[test]
    fn test_snp_report_parse_too_short() {
        let data = vec![0u8; 100];
        assert!(SnpReport::from_bytes(&data).is_err());
    }

    #[test]
    fn test_asn1_integer_parse() {
        // ASN.1 INTEGER encoding of value 3
        let data = [0x02, 0x01, 0x03];
        assert_eq!(parse_asn1_integer(&data), Some(3));

        // ASN.1 INTEGER encoding of value 256
        let data = [0x02, 0x02, 0x01, 0x00];
        assert_eq!(parse_asn1_integer(&data), Some(256));
    }

    // ---------------------------------------------------------------
    // Tests using real SNP attestation report fixtures
    // ---------------------------------------------------------------

    #[test]
    fn test_parse_real_snp_report() {
        // Parse the real 1184-byte SNP attestation report
        let report = SnpReport::from_bytes(TEST_REPORT).expect("failed to parse real SNP report");

        // Verify that key fields are populated (non-zero) for a valid report
        assert!(report.version > 0, "version should be non-zero");
        assert!(report.policy != 0, "policy should be non-zero");
        assert!(
            report.signature_algo != 0,
            "signature_algo should be non-zero"
        );
        assert!(report.current_tcb != 0, "current_tcb should be non-zero");
        assert!(report.reported_tcb != 0, "reported_tcb should be non-zero");
        assert!(report.launch_tcb != 0, "launch_tcb should be non-zero");

        // Measurement must not be all zeroes for a real report
        assert!(
            report.measurement.iter().any(|&b| b != 0),
            "measurement should not be all zeroes"
        );

        // Report data has the first 32 bytes non-zero in the test fixture
        assert!(
            report.report_data.iter().any(|&b| b != 0),
            "report_data should not be all zeroes"
        );

        // Chip ID should be populated
        assert!(
            report.chip_id.iter().any(|&b| b != 0),
            "chip_id should not be all zeroes"
        );

        // Signature R and S components should be non-zero
        assert!(
            report.signature_r[..48].iter().any(|&b| b != 0),
            "signature_r should not be all zeroes"
        );
        assert!(
            report.signature_s[..48].iter().any(|&b| b != 0),
            "signature_s should not be all zeroes"
        );
    }

    #[test]
    fn test_parse_real_snp_report_fields() {
        // Parse and check specific field values from the test-report.bin fixture
        let report = SnpReport::from_bytes(TEST_REPORT).expect("failed to parse real SNP report");

        // Version 2 report
        assert_eq!(report.version, 2);
        assert_eq!(report.guest_svn, 4);
        assert_eq!(report.policy, 0x000000000003001F);
        assert_eq!(report.vmpl, 0);
        assert_eq!(report.signature_algo, 1); // ECDSA P-384 with SHA-384

        // Policy field parsing
        assert_eq!(report.policy_abi_minor, 31);
        assert_eq!(report.policy_abi_major, 0);
        assert!(report.policy_smt_allowed);
        assert!(!report.policy_migrate_ma);
        assert!(!report.policy_debug_allowed);
        assert!(!report.policy_single_socket);

        // Platform info: SMT enabled
        assert!(report.plat_smt_enabled);
        assert!(!report.plat_tsme_enabled);

        // Author key not enabled
        assert_eq!(report.author_key_en, 0);

        // TCB components from the reported_tcb field
        assert_eq!(report.reported_tcb_bootloader, 3);
        assert_eq!(report.reported_tcb_tee, 0);
        assert_eq!(report.reported_tcb_snp, 0);
        assert_eq!(report.reported_tcb_microcode, 115);

        // family_id first byte is 1
        assert_eq!(report.family_id[0], 1);
        // image_id first byte is 2
        assert_eq!(report.image_id[0], 2);

        // Version 2 has no CPUID fields
        assert_eq!(report.cpuid_fam_id, 0);
        assert_eq!(report.cpuid_mod_id, 0);
        assert_eq!(report.cpuid_stepping, 0);

        // Verify report_data starts with known bytes
        assert_eq!(report.report_data[0], 0xec);
        assert_eq!(report.report_data[1], 0x6c);

        // Verify measurement starts with known bytes
        assert_eq!(report.measurement[0], 0xa1);
        assert_eq!(report.measurement[1], 0xf3);

        // Host data is all zeroes in this test fixture
        assert!(report.host_data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_parse_vlek_report() {
        // Parse the VLEK report fixture (version 3, different from the VCEK report)
        let report = SnpReport::from_bytes(TEST_VLEK_REPORT).expect("failed to parse VLEK report");

        assert_eq!(report.version, 3);
        assert_eq!(report.guest_svn, 0);
        assert_eq!(report.policy, 0x0000000000030000);
        assert_eq!(report.vmpl, 1); // VLEK report has VMPL=1
        assert_eq!(report.signature_algo, 1);
        assert_eq!(report.author_key_en, 4); // Author key enabled for VLEK

        // Measurement must not be all zeroes
        assert!(report.measurement.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_snp_report_tamper_detection() {
        // Verify that flipping a byte in the signed portion of the report
        // causes signature verification to fail.
        let mut tampered = TEST_REPORT.to_vec();

        // Flip a byte in the measurement field (offset 0x90), which is
        // inside the signed portion (0x00..0x2A0)
        tampered[0x90] ^= 0xFF;

        // The report should still parse (structure is valid)
        let _report = SnpReport::from_bytes(&tampered).expect("tampered report should still parse");

        // But signature verification against the VCEK should fail
        let result = verify_report_signature(&tampered, TEST_VCEK);
        assert!(
            result.is_err(),
            "signature verification should fail on tampered report"
        );
    }

    #[test]
    fn test_snp_report_signature_tamper_detection() {
        // Tamper with the signature itself (outside signed region but part of sig)
        let mut tampered = TEST_REPORT.to_vec();

        // Flip a byte in the R component of the signature (offset 0x2A0)
        tampered[0x2A0] ^= 0xFF;

        // Signature verification should fail
        let result = verify_report_signature(&tampered, TEST_VCEK);
        assert!(
            result.is_err(),
            "signature verification should fail when signature bytes are tampered"
        );
    }

    #[test]
    fn test_cert_chain_validation_milan_rsa_pss() {
        // Milan ARK/ASK use RSA-PSS SHA-384 to sign certs.
        // verify_cert_chain now supports both RSA-PSS and ECDSA P-384.
        let (ark_der, ask_der) = super::super::certs::get_bundled_certs(ProcessorGeneration::Milan);

        let result = verify_cert_chain(ark_der, ask_der, TEST_VCEK);
        assert!(
            result.is_ok(),
            "Milan RSA-PSS cert chain should verify successfully: {:?}",
            result.err()
        );
    }

    // --- Azure IMDS real certificate integration tests ---

    #[test]
    fn test_imds_vcek_parses_as_x509() {
        let cert =
            x509_cert::Certificate::from_der(IMDS_VCEK).expect("IMDS VCEK should parse as X.509");

        let subject = format!("{}", cert.tbs_certificate.subject);
        assert!(
            subject.contains("SEV-VCEK"),
            "IMDS VCEK subject should contain SEV-VCEK, got: {}",
            subject
        );

        let issuer = format!("{}", cert.tbs_certificate.issuer);
        assert!(
            issuer.contains("SEV-Milan"),
            "IMDS VCEK issuer should reference SEV-Milan, got: {}",
            issuer
        );
    }

    #[test]
    fn test_imds_ask_parses_as_x509() {
        let cert =
            x509_cert::Certificate::from_der(IMDS_ASK).expect("IMDS ASK should parse as X.509");

        let subject = format!("{}", cert.tbs_certificate.subject);
        assert!(
            subject.contains("SEV-Milan"),
            "IMDS ASK subject should contain SEV-Milan, got: {}",
            subject
        );

        let issuer = format!("{}", cert.tbs_certificate.issuer);
        assert!(
            issuer.contains("ARK-Milan"),
            "IMDS ASK issuer should reference ARK-Milan, got: {}",
            issuer
        );
    }

    #[test]
    fn test_imds_ark_is_self_signed() {
        let cert =
            x509_cert::Certificate::from_der(IMDS_ARK).expect("IMDS ARK should parse as X.509");

        assert_eq!(
            cert.tbs_certificate.issuer, cert.tbs_certificate.subject,
            "IMDS ARK should be self-signed"
        );

        let subject = format!("{}", cert.tbs_certificate.subject);
        assert!(
            subject.contains("ARK-Milan"),
            "IMDS ARK subject should contain ARK-Milan, got: {}",
            subject
        );
    }

    #[test]
    fn test_imds_full_cert_chain_verification() {
        // End-to-end: verify the real Azure IMDS cert chain (ARK -> ASK -> VCEK)
        // All three use RSA-PSS SHA-384 signatures (Milan processor generation)
        let result = verify_cert_chain(IMDS_ARK, IMDS_ASK, IMDS_VCEK);
        assert!(
            result.is_ok(),
            "real IMDS cert chain (ARK -> ASK -> VCEK) should verify: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_imds_cert_chain_matches_bundled_ark() {
        // The IMDS ARK should match our bundled Milan ARK
        let (bundled_ark, _) = super::super::certs::get_bundled_certs(ProcessorGeneration::Milan);

        // Parse both and compare subjects
        let imds_ark = x509_cert::Certificate::from_der(IMDS_ARK).expect("IMDS ARK parse");
        let bundled = x509_cert::Certificate::from_der(bundled_ark).expect("bundled ARK parse");

        assert_eq!(
            imds_ark.tbs_certificate.subject, bundled.tbs_certificate.subject,
            "IMDS ARK subject should match bundled ARK subject"
        );

        // The public keys should also match (same root of trust)
        let imds_pk = imds_ark
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();
        let bundled_pk = bundled
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();
        assert_eq!(
            imds_pk, bundled_pk,
            "IMDS ARK public key should match bundled ARK public key"
        );
    }

    #[test]
    fn test_imds_cert_chain_with_bundled_certs() {
        // Verify IMDS VCEK against bundled Milan certs (not IMDS certs)
        // This proves the IMDS VCEK is in the real AMD chain of trust
        let (ark_der, ask_der) = super::super::certs::get_bundled_certs(ProcessorGeneration::Milan);

        let result = verify_cert_chain(ark_der, ask_der, IMDS_VCEK);
        assert!(
            result.is_ok(),
            "IMDS VCEK should verify against bundled Milan certs: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_imds_cert_chain_wrong_generation_fails() {
        // IMDS certs are Milan; using Genoa certs should fail
        let (ark_der, ask_der) = super::super::certs::get_bundled_certs(ProcessorGeneration::Genoa);

        let result = verify_cert_chain(ark_der, ask_der, IMDS_VCEK);
        assert!(
            result.is_err(),
            "IMDS VCEK should not verify against Genoa certs"
        );
    }

    #[test]
    fn test_imds_vcek_tcb_extraction() {
        // Extract TCB from the real IMDS VCEK certificate
        let tcb = extract_vcek_tcb(IMDS_VCEK).expect("should extract TCB from IMDS VCEK");

        // The IMDS TCBM was DB18000000000004, which maps to:
        // microcode=0xDB(219), snp=0x18(24), bootloader=4, tee=0
        assert_eq!(tcb.microcode, 219, "microcode should be 0xDB=219");
        assert_eq!(tcb.snp, 24, "snp should be 0x18=24");
        assert_eq!(tcb.bootloader, 4, "bootloader should be 4");
        assert_eq!(tcb.tee, 0, "tee should be 0");
    }

    #[test]
    fn test_imds_vcek_has_ecdsa_p384_key() {
        // The VCEK should have an ECDSA P-384 public key
        let cert = x509_cert::Certificate::from_der(IMDS_VCEK).expect("IMDS VCEK parse");

        let spki = &cert.tbs_certificate.subject_public_key_info;
        let algo_oid = spki.algorithm.oid.to_string();

        // OID 1.2.840.10045.2.1 = id-ecPublicKey
        assert_eq!(
            algo_oid, "1.2.840.10045.2.1",
            "VCEK should use EC public key algorithm"
        );

        // Should be parseable as P-384 key
        let key_bytes = spki.subject_public_key.raw_bytes();
        let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes);
        assert!(
            vk.is_ok(),
            "VCEK public key should be a valid P-384 point: {:?}",
            vk.err()
        );
    }

    #[test]
    fn test_cert_chain_wrong_generation_fails() {
        // Using Genoa certs to validate a Milan VCEK should fail
        let (ark_der, ask_der) = super::super::certs::get_bundled_certs(ProcessorGeneration::Genoa);

        let result = verify_cert_chain(ark_der, ask_der, TEST_VCEK);
        assert!(
            result.is_err(),
            "cert chain validation should fail with wrong generation certs"
        );
    }

    #[test]
    fn test_cert_chain_invalid_vcek_legacy() {
        // The invalid-legacy VCEK should fail cert chain validation
        let (ark_der, ask_der) = super::super::certs::get_bundled_certs(ProcessorGeneration::Milan);

        let result = verify_cert_chain(ark_der, ask_der, TEST_VCEK_INVALID_LEGACY);
        assert!(
            result.is_err(),
            "cert chain validation should fail for invalid legacy VCEK"
        );
    }

    #[test]
    fn test_cert_chain_invalid_vcek_new() {
        // The invalid-new VCEK should fail cert chain validation
        let (ark_der, ask_der) = super::super::certs::get_bundled_certs(ProcessorGeneration::Milan);

        let result = verify_cert_chain(ark_der, ask_der, TEST_VCEK_INVALID_NEW);
        assert!(
            result.is_err(),
            "cert chain validation should fail for invalid new VCEK"
        );
    }

    #[test]
    fn test_cert_chain_ark_self_signed_check() {
        // The Milan ARK should be self-signed (issuer == subject)
        let (ark_der, _ask_der) =
            super::super::certs::get_bundled_certs(ProcessorGeneration::Milan);
        let ark_cert = x509_cert::Certificate::from_der(ark_der).expect("failed to parse ARK cert");
        assert_eq!(
            ark_cert.tbs_certificate.issuer, ark_cert.tbs_certificate.subject,
            "ARK should be self-signed"
        );
    }

    #[test]
    fn test_cert_chain_ask_issued_by_ark() {
        // The ASK should be issued by the ARK
        let (ark_der, ask_der) = super::super::certs::get_bundled_certs(ProcessorGeneration::Milan);
        let ark_cert = x509_cert::Certificate::from_der(ark_der).expect("failed to parse ARK cert");
        let ask_cert = x509_cert::Certificate::from_der(ask_der).expect("failed to parse ASK cert");
        assert_eq!(
            ask_cert.tbs_certificate.issuer, ark_cert.tbs_certificate.subject,
            "ASK issuer should match ARK subject"
        );
    }

    #[test]
    fn test_vcek_issued_by_ask() {
        // The VCEK should be issued by the ASK (SEV-Milan)
        let (_ark_der, ask_der) =
            super::super::certs::get_bundled_certs(ProcessorGeneration::Milan);
        let ask_cert = x509_cert::Certificate::from_der(ask_der).expect("failed to parse ASK cert");
        let vcek_cert =
            x509_cert::Certificate::from_der(TEST_VCEK).expect("failed to parse VCEK cert");
        assert_eq!(
            vcek_cert.tbs_certificate.issuer, ask_cert.tbs_certificate.subject,
            "VCEK issuer should match ASK subject"
        );
    }

    #[test]
    fn test_report_signature_extraction() {
        // Verify we can extract and parse the signature R and S components
        // from a real report and construct a valid ECDSA P-384 signature.
        let report = SnpReport::from_bytes(TEST_REPORT).expect("failed to parse real SNP report");

        // R component: first 48 of the 72-byte field, little-endian
        let sig_r = &report.signature_r[..48];
        let sig_s = &report.signature_s[..48];

        // Both R and S should be non-zero
        assert!(sig_r.iter().any(|&b| b != 0), "R should not be all zeroes");
        assert!(sig_s.iter().any(|&b| b != 0), "S should not be all zeroes");

        // Convert to big-endian and construct a P-384 signature
        let mut r_be = [0u8; 48];
        let mut s_be = [0u8; 48];
        for i in 0..48 {
            r_be[i] = sig_r[47 - i];
            s_be[i] = sig_s[47 - i];
        }

        let signature = p384::ecdsa::Signature::from_scalars(
            p384::FieldBytes::from(r_be),
            p384::FieldBytes::from(s_be),
        );
        assert!(
            signature.is_ok(),
            "should be able to construct P-384 signature from report: {:?}",
            signature.err()
        );
    }

    #[test]
    fn test_report_signature_valid_against_vcek() {
        // End-to-end: verify the real report signature against the real VCEK
        let result = verify_report_signature(TEST_REPORT, TEST_VCEK);
        assert!(
            result.is_ok(),
            "real report signature should verify against real VCEK: {:?}",
            result.err()
        );
        assert!(result.unwrap(), "signature should be valid");
    }

    #[test]
    fn test_vcek_cert_parses() {
        // Verify the VCEK DER certificate can be parsed as X.509
        let cert = x509_cert::Certificate::from_der(TEST_VCEK);
        assert!(
            cert.is_ok(),
            "VCEK DER should parse as X.509: {:?}",
            cert.err()
        );

        let cert = cert.unwrap();
        // Issuer should reference AMD (issuer DN contains "Advanced Micro Devices")
        let issuer = format!("{}", cert.tbs_certificate.issuer);
        assert!(
            issuer.contains("Advanced Micro Devices"),
            "VCEK issuer should reference Advanced Micro Devices, got: {}",
            issuer
        );
        // Subject should be SEV-VCEK
        let subject = format!("{}", cert.tbs_certificate.subject);
        assert!(
            subject.contains("SEV-VCEK"),
            "VCEK subject should contain SEV-VCEK, got: {}",
            subject
        );
    }

    #[test]
    fn test_vlek_cert_parses() {
        // Verify the VLEK DER certificate can be parsed as X.509
        let cert = x509_cert::Certificate::from_der(TEST_VLEK);
        assert!(
            cert.is_ok(),
            "VLEK DER should parse as X.509: {:?}",
            cert.err()
        );
    }

    #[test]
    fn test_extract_vcek_tcb_from_real_cert() {
        // Extract TCB values from the real VCEK certificate extensions
        let tcb = extract_vcek_tcb(TEST_VCEK).expect("should extract TCB from VCEK");

        // TCB components should be populated (at least some non-zero)
        let has_nonzero = tcb.bootloader != 0 || tcb.tee != 0 || tcb.snp != 0 || tcb.microcode != 0;
        assert!(
            has_nonzero,
            "at least one TCB component should be non-zero: {:?}",
            tcb
        );
    }

    #[test]
    fn test_report_exact_size() {
        // Verify the test report fixture is exactly 1184 bytes
        assert_eq!(TEST_REPORT.len(), 1184);
    }

    #[test]
    fn test_vlek_report_exact_size() {
        assert_eq!(TEST_VLEK_REPORT.len(), 1184);
    }

    #[test]
    fn test_parse_report_boundary_at_1184() {
        // Exactly 1184 bytes should work
        let data = vec![0u8; 1184];
        assert!(SnpReport::from_bytes(&data).is_ok());

        // 1183 bytes should fail
        let data = vec![0u8; 1183];
        assert!(SnpReport::from_bytes(&data).is_err());

        // More than 1184 bytes should also work (extra bytes ignored)
        let data = vec![0u8; 2000];
        assert!(SnpReport::from_bytes(&data).is_ok());
    }
}
