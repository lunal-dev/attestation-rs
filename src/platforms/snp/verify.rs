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

        // CPUID fields (only valid in version >= 3)
        let cpuid_fam_id = if version >= 3 { data[0x1F8] } else { 0 };
        let cpuid_mod_id = if version >= 3 { data[0x1F9] } else { 0 };
        let cpuid_stepping = if version >= 3 { data[0x1FA] } else { 0 };

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

/// Verify that `issuer_cert` signed `subject_cert` using ECDSA P-384.
fn verify_cert_signature(
    issuer_cert: &x509_cert::Certificate,
    subject_cert: &x509_cert::Certificate,
) -> Result<()> {
    use der::Encode;
    use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    // Extract the public key from the issuer
    let issuer_spki = &issuer_cert.tbs_certificate.subject_public_key_info;
    let pub_key_bytes = issuer_spki.subject_public_key.raw_bytes();

    let verifying_key = VerifyingKey::from_sec1_bytes(pub_key_bytes)
        .map_err(|e| AttestationError::CertChainError(format!("issuer pubkey: {}", e)))?;

    // The TBS (to-be-signed) certificate bytes
    let tbs_bytes = subject_cert
        .tbs_certificate
        .to_der()
        .map_err(|e| AttestationError::CertChainError(format!("TBS encode: {}", e)))?;

    // The signature from the subject cert
    let sig_bytes = subject_cert.signature.raw_bytes();

    let signature = Signature::from_der(sig_bytes)
        .map_err(|e| AttestationError::CertChainError(format!("signature parse: {}", e)))?;

    // AMD certs use SHA-384 with ECDSA P-384
    // The p384 crate's VerifyingKey.verify() uses SHA-384 by default
    verifying_key
        .verify(&tbs_bytes, &signature)
        .map_err(|e| AttestationError::CertChainError(format!("signature verify: {}", e)))?;

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

    let verifying_key = VerifyingKey::from_sec1_bytes(pub_key_bytes)
        .map_err(|e| AttestationError::SignatureVerificationFailed(format!("VCEK pubkey: {}", e)))?;

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

    let r_bytes: p384::FieldBytes = *p384::FieldBytes::from_slice(&r_be);
    let s_bytes: p384::FieldBytes = *p384::FieldBytes::from_slice(&s_be);
    let signature = Signature::from_scalars(r_bytes, s_bytes)
    .map_err(|e| AttestationError::SignatureVerificationFailed(format!("sig construct: {}", e)))?;

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
}
