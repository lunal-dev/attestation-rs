//! DCAP (Data Center Attestation Primitives) chain verification for TDX quotes.
//!
//! **Phase 1** (always-on, no network):
//! 1. PCK certificate chain validation (leaf → intermediate → Intel Root CA)
//! 2. QE report signature verification (signed by PCK leaf key)
//! 3. QE report binding (attestation key is bound into QE report data)
//!
//! **Phase 2** (optional, needs network via `TdxCollateralProvider`):
//! 4. FMSPC extraction from PCK cert extensions
//! 5. TCB status evaluation against Intel collateral
//! 6. CRL revocation checking

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use der::Decode;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use scroll::Pread;
use sha2::{Digest, Sha256};
use x509_parser::der_parser::ber::BerObjectContent;
use x509_parser::der_parser::der::parse_der_sequence;
use x509_parser::prelude::{CertificateRevocationList, FromDer, X509Certificate};

use crate::error::{AttestationError, Result};
use crate::types::{DcapVerificationStatus, TdxTcbStatus};

use super::verify::{QuoteVersion, QUOTE_HEADER_SIZE, REPORT_BODY_SIZE};

/// Intel SGX Root CA public key (ECDSA P-256, uncompressed SEC1).
///
/// This is the trust anchor for all DCAP attestation. Every legitimate
/// PCK certificate chain terminates at this root key.
const INTEL_SGX_ROOT_CA_PUB_DER: &[u8] = &[
    0x04, // SEC1 uncompressed point prefix
    // X coordinate (32 bytes)
    0x0b, 0xa9, 0xc4, 0xc0, 0xc0, 0xc8, 0x61, 0x93, 0xa3, 0xfe, 0x23, 0xd6, 0xb0, 0x2c, 0xda,
    0x10, 0xa8, 0xbb, 0xd4, 0xe8, 0x8e, 0x48, 0xb4, 0x45, 0x85, 0x61, 0xa3, 0x6e, 0x70, 0x55,
    0x25, 0xf5,
    // Y coordinate (32 bytes)
    0x67, 0x91, 0x8e, 0x2e, 0xdc, 0x88, 0xe4, 0x0d, 0x86, 0x0b, 0xd0, 0xcc, 0x4e, 0xe2, 0x6a,
    0xac, 0xc9, 0x88, 0xe5, 0x05, 0xa9, 0x53, 0x55, 0x8c, 0x45, 0x3f, 0x6b, 0x09, 0x04, 0xae,
    0x73, 0x94,
];

/// QE (Quoting Enclave) report body size in bytes.
const QE_REPORT_BODY_SIZE: usize = 384;

/// Cert data type: ECDSA signature aux data (contains QE report + nested cert chain).
const CERT_DATA_TYPE_ECDSA_SIG_AUX: u16 = 6;

/// Cert data type: PCK certificate chain (PEM-encoded leaf + intermediate + root).
const CERT_DATA_TYPE_PCK_CHAIN: u16 = 5;

/// Parsed auth data from a TDX quote (v4+).
pub struct QuoteAuthData<'a> {
    /// ECDSA P-256 attestation public key (64 bytes: X || Y)
    pub attestation_pub_key: &'a [u8],
    /// QE report body (384 bytes)
    pub qe_report_body: &'a [u8],
    /// QE report ECDSA P-256 signature (64 bytes)
    pub qe_report_signature: &'a [u8],
    /// QE authentication data (variable length)
    pub qe_auth_data: &'a [u8],
    /// PEM-encoded PCK certificate chain
    pub pck_cert_chain_pem: &'a [u8],
}

/// Parse the full auth data section from a TDX quote.
///
/// Layout for v4+:
/// ```text
/// [body_end + 0]:  sig_data_len (4 bytes LE)
/// [body_end + 4]:  ECDSA signature (64 bytes) — already verified by verify_quote_signature
/// [body_end + 68]: attestation public key (64 bytes)
/// [body_end + 132]: cert_data_type (2 bytes LE) — must be 6 (EcdsaSigAuxData)
/// [body_end + 134]: cert_data_size (4 bytes LE)
/// [body_end + 138]: cert_data contents:
///     [+0]:   QE report body (384 bytes)
///     [+384]: QE report signature (64 bytes)
///     [+448]: qe_auth_data_size (2 bytes LE)
///     [+450]: qe_auth_data (variable)
///     [+450+auth_size]: nested cert_data_type (2 bytes LE) — must be 5 (PckCertChain)
///     [+452+auth_size]: nested cert_data_size (4 bytes LE)
///     [+456+auth_size]: PEM cert chain data
/// ```
pub fn parse_auth_data<'a>(quote_bytes: &'a [u8], body_end: usize) -> Result<QuoteAuthData<'a>> {
    let err = |msg: String| AttestationError::QuoteParseFailed(msg);

    // Skip past sig_data_len(4) + signature(64)
    let attest_key_offset = body_end + 4 + 64;
    if quote_bytes.len() < attest_key_offset + 64 {
        return Err(err("quote too short for attestation key".into()));
    }
    let attestation_pub_key = &quote_bytes[attest_key_offset..attest_key_offset + 64];

    // Read outer cert_data header (type 6)
    let cert_type_offset = attest_key_offset + 64;
    if quote_bytes.len() < cert_type_offset + 6 {
        return Err(err("quote too short for cert data header".into()));
    }
    let cert_data_type = quote_bytes
        .pread_with::<u16>(cert_type_offset, scroll::LE)
        .map_err(|e| err(format!("cert_data_type: {}", e)))?;
    if cert_data_type != CERT_DATA_TYPE_ECDSA_SIG_AUX {
        return Err(err(format!(
            "expected cert_data_type {} (EcdsaSigAuxData), got {}",
            CERT_DATA_TYPE_ECDSA_SIG_AUX, cert_data_type
        )));
    }
    let cert_data_size = quote_bytes
        .pread_with::<u32>(cert_type_offset + 2, scroll::LE)
        .map_err(|e| err(format!("cert_data_size: {}", e)))? as usize;

    let cert_data_start = cert_type_offset + 6;
    if quote_bytes.len() < cert_data_start + cert_data_size {
        return Err(err(format!(
            "quote too short for cert data: need {} bytes at offset {}, have {}",
            cert_data_size,
            cert_data_start,
            quote_bytes.len()
        )));
    }
    let cert_data = &quote_bytes[cert_data_start..cert_data_start + cert_data_size];

    // Parse QE report body (384 bytes)
    if cert_data.len() < QE_REPORT_BODY_SIZE + 64 {
        return Err(err("cert data too short for QE report + signature".into()));
    }
    let qe_report_body = &cert_data[..QE_REPORT_BODY_SIZE];
    let qe_report_signature = &cert_data[QE_REPORT_BODY_SIZE..QE_REPORT_BODY_SIZE + 64];

    // Parse QE auth data
    let auth_size_offset = QE_REPORT_BODY_SIZE + 64;
    if cert_data.len() < auth_size_offset + 2 {
        return Err(err("cert data too short for qe_auth_data_size".into()));
    }
    let qe_auth_data_size = cert_data
        .pread_with::<u16>(auth_size_offset, scroll::LE)
        .map_err(|e| err(format!("qe_auth_data_size: {}", e)))? as usize;

    let qe_auth_data_start = auth_size_offset + 2;
    if cert_data.len() < qe_auth_data_start + qe_auth_data_size {
        return Err(err("cert data too short for qe_auth_data".into()));
    }
    let qe_auth_data = &cert_data[qe_auth_data_start..qe_auth_data_start + qe_auth_data_size];

    // Parse nested cert data (type 5 = PckCertChain)
    let nested_offset = qe_auth_data_start + qe_auth_data_size;
    if cert_data.len() < nested_offset + 6 {
        return Err(err("cert data too short for nested cert data header".into()));
    }
    let nested_type = cert_data
        .pread_with::<u16>(nested_offset, scroll::LE)
        .map_err(|e| err(format!("nested cert_data_type: {}", e)))?;
    if nested_type != CERT_DATA_TYPE_PCK_CHAIN {
        return Err(err(format!(
            "expected nested cert_data_type {} (PckCertChain), got {}",
            CERT_DATA_TYPE_PCK_CHAIN, nested_type
        )));
    }
    let nested_size = cert_data
        .pread_with::<u32>(nested_offset + 2, scroll::LE)
        .map_err(|e| err(format!("nested cert_data_size: {}", e)))? as usize;

    let pem_start = nested_offset + 6;
    if cert_data.len() < pem_start + nested_size {
        return Err(err("cert data too short for PEM cert chain".into()));
    }
    let pck_cert_chain_pem = &cert_data[pem_start..pem_start + nested_size];

    Ok(QuoteAuthData {
        attestation_pub_key,
        qe_report_body,
        qe_report_signature,
        qe_auth_data,
        pck_cert_chain_pem,
    })
}

/// Verify that the attestation key is bound into the QE report.
///
/// The QE report's user_report_data must equal:
///   SHA-256(attestation_pub_key || qe_auth_data) || 32 zero bytes
pub fn verify_qe_report_binding(auth_data: &QuoteAuthData) -> Result<()> {
    let mut hasher = Sha256::new();
    hasher.update(auth_data.attestation_pub_key);
    hasher.update(auth_data.qe_auth_data);
    let digest = hasher.finalize();

    // user_report_data is at offset 320 in the QE report body (64 bytes)
    let user_report_data = &auth_data.qe_report_body[320..384];

    // First 32 bytes must match the hash
    if !crate::utils::constant_time_eq(&user_report_data[..32], &digest) {
        return Err(AttestationError::SignatureVerificationFailed(
            "QE report binding failed: SHA-256(attest_key || auth_data) != report_data[0:32]"
                .into(),
        ));
    }

    // Last 32 bytes must be zero
    if user_report_data[32..64].iter().any(|&b| b != 0) {
        return Err(AttestationError::SignatureVerificationFailed(
            "QE report binding failed: report_data[32:64] is not zero-padded".into(),
        ));
    }

    Ok(())
}

/// Verify the QE report signature using the PCK leaf certificate's public key.
///
/// The PCK leaf cert signs the 384-byte QE report body with ECDSA P-256.
pub fn verify_qe_report_signature(
    auth_data: &QuoteAuthData,
    pck_pub_key: &VerifyingKey,
) -> Result<()> {
    let sig = Signature::from_slice(auth_data.qe_report_signature).map_err(|e| {
        AttestationError::SignatureVerificationFailed(format!("QE report signature parse: {}", e))
    })?;

    pck_pub_key
        .verify(auth_data.qe_report_body, &sig)
        .map_err(|e| {
            AttestationError::SignatureVerificationFailed(format!(
                "QE report signature verification: {}",
                e
            ))
        })
}

/// Validate the PCK certificate chain and return the PCK leaf's public key.
///
/// Expects a PEM blob with 3 certificates:
///   [0] PCK leaf cert
///   [1] PCK Platform CA (intermediate)
///   [2] Intel SGX Root CA
///
/// Validates:
///   - Root CA public key matches hardcoded Intel trust anchor
///   - Root CA self-signs correctly
///   - Intermediate is signed by Root CA
///   - Leaf is signed by Intermediate
///
/// Returns the PCK leaf's ECDSA P-256 public key for QE report signature verification.
pub fn verify_pck_cert_chain(pem_data: &[u8]) -> Result<VerifyingKey> {
    let pem_str = std::str::from_utf8(pem_data).map_err(|e| {
        AttestationError::CertChainError(format!("PEM data is not valid UTF-8: {}", e))
    })?;

    // Split PEM into individual DER-encoded certificates
    let der_certs = split_pem_to_der(pem_str)?;

    if der_certs.len() < 3 {
        return Err(AttestationError::CertChainError(format!(
            "expected at least 3 certificates in PCK chain, got {}",
            der_certs.len()
        )));
    }

    // Parse certificates to extract TBS data and public keys
    let leaf_cert = parse_x509_cert(&der_certs[0], "PCK leaf")?;
    let intermediate_cert = parse_x509_cert(&der_certs[1], "PCK Platform CA")?;
    let root_cert = parse_x509_cert(&der_certs[2], "Intel SGX Root CA")?;

    // Step 1: Verify Root CA public key matches hardcoded Intel key
    let root_pub_key = extract_p256_pub_key(&root_cert.pub_key_bytes, "Root CA")?;
    let intel_root_key = VerifyingKey::from_sec1_bytes(INTEL_SGX_ROOT_CA_PUB_DER).map_err(|e| {
        AttestationError::CertChainError(format!("Intel Root CA key parse: {}", e))
    })?;

    if root_pub_key.to_encoded_point(false) != intel_root_key.to_encoded_point(false) {
        return Err(AttestationError::CertChainError(
            "Root CA public key does not match Intel SGX Root CA".into(),
        ));
    }

    // Step 2: Verify Root CA self-signature
    verify_cert_signature(&root_cert, &root_pub_key, "Root CA self-signature")?;

    // Step 3: Verify Intermediate is signed by Root CA
    let intermediate_pub_key =
        extract_p256_pub_key(&intermediate_cert.pub_key_bytes, "Intermediate CA")?;
    verify_cert_signature(&intermediate_cert, &root_pub_key, "Intermediate cert")?;

    // Step 4: Verify Leaf is signed by Intermediate
    verify_cert_signature(&leaf_cert, &intermediate_pub_key, "PCK leaf cert")?;

    extract_p256_pub_key(&leaf_cert.pub_key_bytes, "PCK leaf")
}

/// Minimal X.509 certificate data needed for chain verification.
struct CertData {
    /// Raw TBS (To-Be-Signed) certificate bytes (the signed content)
    tbs_bytes: Vec<u8>,
    /// ECDSA signature on the TBS data
    signature_bytes: Vec<u8>,
    /// Subject public key bytes (SEC1 encoded)
    pub_key_bytes: Vec<u8>,
}

/// Parse a DER-encoded X.509 certificate and extract the fields we need.
fn parse_x509_cert(der: &[u8], label: &str) -> Result<CertData> {
    // X.509 Certificate structure (DER/ASN.1):
    //   SEQUENCE {
    //     tbsCertificate      TBSCertificate,        -- SEQUENCE
    //     signatureAlgorithm  AlgorithmIdentifier,   -- SEQUENCE
    //     signatureValue      BIT STRING
    //   }
    //
    // We need:
    //   - The raw bytes of tbsCertificate (for signature verification)
    //   - The signatureValue (the actual ECDSA signature)
    //   - The subjectPublicKeyInfo from tbsCertificate

    let cert = x509_cert::Certificate::from_der(der).map_err(|e| {
        AttestationError::CertChainError(format!("{} cert DER parse: {}", label, e))
    })?;

    // Extract TBS bytes: re-encode the TBS certificate to DER
    let tbs_bytes = der::Encode::to_der(&cert.tbs_certificate).map_err(|e| {
        AttestationError::CertChainError(format!("{} TBS DER encode: {}", label, e))
    })?;

    // Extract signature bytes (strip leading zero byte if present for ASN.1 BIT STRING)
    let sig_bits = cert.signature.raw_bytes();
    let signature_bytes = sig_bits.to_vec();

    // Extract subject public key bytes
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let pub_key_raw = spki
        .subject_public_key
        .raw_bytes();
    let pub_key_bytes = pub_key_raw.to_vec();

    Ok(CertData {
        tbs_bytes,
        signature_bytes,
        pub_key_bytes,
    })
}

/// Extract a P-256 verifying key from SEC1-encoded public key bytes.
fn extract_p256_pub_key(pub_key_bytes: &[u8], label: &str) -> Result<VerifyingKey> {
    VerifyingKey::from_sec1_bytes(pub_key_bytes).map_err(|e| {
        AttestationError::CertChainError(format!("{} public key parse: {}", label, e))
    })
}

/// Verify a certificate's signature using the issuer's public key.
fn verify_cert_signature(
    cert: &CertData,
    issuer_key: &VerifyingKey,
    label: &str,
) -> Result<()> {
    // The signature in X.509 is DER-encoded (ASN.1 SEQUENCE of two INTEGERs)
    let sig = Signature::from_der(&cert.signature_bytes).map_err(|e| {
        AttestationError::CertChainError(format!("{} signature parse: {}", label, e))
    })?;

    issuer_key.verify(&cert.tbs_bytes, &sig).map_err(|e| {
        AttestationError::CertChainError(format!("{} signature verification: {}", label, e))
    })
}

/// Split a PEM string into individual DER-encoded certificate blobs.
fn split_pem_to_der(pem_str: &str) -> Result<Vec<Vec<u8>>> {
    let mut certs = Vec::new();
    let mut current = String::new();
    let mut in_cert = false;

    for line in pem_str.lines() {
        if line.contains("BEGIN CERTIFICATE") {
            in_cert = true;
            current.clear();
        } else if line.contains("END CERTIFICATE") {
            in_cert = false;
            let der = BASE64.decode(current.trim()).map_err(|e| {
                AttestationError::CertChainError(format!("PEM base64 decode: {}", e))
            })?;
            certs.push(der);
        } else if in_cert {
            current.push_str(line.trim());
        }
    }

    Ok(certs)
}

/// Compute where the quote body ends (i.e., where auth data begins).
pub fn compute_body_end(quote_bytes: &[u8], quote_version: QuoteVersion) -> Result<usize> {
    match quote_version {
        QuoteVersion::V4 => Ok(QUOTE_HEADER_SIZE + REPORT_BODY_SIZE),
        QuoteVersion::V5Tdx10 | QuoteVersion::V5Tdx15 => {
            let body_size = quote_bytes
                .pread_with::<u32>(QUOTE_HEADER_SIZE + 2, scroll::LE)
                .map_err(|e| {
                    AttestationError::QuoteParseFailed(format!("v5 body size: {}", e))
                })? as usize;
            Ok(QUOTE_HEADER_SIZE + 6 + body_size)
        }
    }
}

/// Run the full DCAP chain verification on a TDX quote.
///
/// This is a convenience function that runs all Phase 1 DCAP checks:
/// 1. Parse auth data from the quote
/// 2. Validate PCK certificate chain to Intel Root CA
/// 3. Verify QE report signature with PCK leaf key
/// 4. Verify QE report binding (attestation key bound into QE report)
pub fn verify_dcap_chain(quote_bytes: &[u8], quote_version: QuoteVersion) -> Result<()> {
    let body_end = compute_body_end(quote_bytes, quote_version)?;
    let auth = parse_auth_data(quote_bytes, body_end)?;
    let pck_pub_key = verify_pck_cert_chain(auth.pck_cert_chain_pem)?;
    verify_qe_report_signature(&auth, &pck_pub_key)?;
    verify_qe_report_binding(&auth)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 2: TCB status evaluation, FMSPC extraction, CRL checking
// ---------------------------------------------------------------------------

/// SGX Extensions OID: 1.2.840.113741.1.13.1
const SGX_EXTENSIONS_OID: &[u64] = &[1, 2, 840, 113741, 1, 13, 1];

/// FMSPC OID: 1.2.840.113741.1.13.1.4
const FMSPC_OID: &[u64] = &[1, 2, 840, 113741, 1, 13, 1, 4];

/// Extract the FMSPC (Family-Model-Stepping-Platform-CustomSKU) from a PCK leaf cert.
///
/// The FMSPC is a 6-byte value embedded in the SGX extensions of the PCK certificate,
/// under OID 1.2.840.113741.1.13.1.4. It identifies the platform for TCB Info lookup.
pub fn extract_fmspc_from_pck(pem_data: &[u8]) -> Result<String> {
    let pem_str = std::str::from_utf8(pem_data).map_err(|e| {
        AttestationError::CertChainError(format!("PEM not UTF-8: {}", e))
    })?;

    // Get just the first (leaf) cert
    let der_certs = split_pem_to_der(pem_str)?;
    if der_certs.is_empty() {
        return Err(AttestationError::CertChainError(
            "no certificates found in PEM data".into(),
        ));
    }

    let (_, cert) = X509Certificate::from_der(&der_certs[0]).map_err(|e| {
        AttestationError::CertChainError(format!("PCK leaf x509 parse: {}", e))
    })?;

    // Find the SGX extensions OID in the cert extensions
    let sgx_ext_oid = x509_parser::oid_registry::Oid::from(SGX_EXTENSIONS_OID)
        .expect("SGX_EXTENSIONS_OID is valid");

    for ext in cert.extensions() {
        if ext.oid == sgx_ext_oid {
            // The SGX extension value is an ASN.1 SEQUENCE of SEQUENCE { OID, value }
            return extract_fmspc_from_sgx_extension(ext.value);
        }
    }

    Err(AttestationError::CertChainError(
        "SGX extensions OID not found in PCK certificate".into(),
    ))
}

/// Parse the SGX extension ASN.1 blob and extract the FMSPC value.
fn extract_fmspc_from_sgx_extension(data: &[u8]) -> Result<String> {
    let fmspc_oid = x509_parser::oid_registry::Oid::from(FMSPC_OID)
        .expect("FMSPC_OID is valid");

    // Parse outer SEQUENCE
    let (_, seq) = parse_der_sequence(data).map_err(|e| {
        AttestationError::CertChainError(format!("SGX extension parse: {}", e))
    })?;

    // Each element is a SEQUENCE { OID, value }
    for item in seq.ref_iter() {
        if let BerObjectContent::Sequence(ref inner) = item.content {
            if inner.len() >= 2 {
                if let BerObjectContent::OID(ref oid) = inner[0].content {
                    if *oid == fmspc_oid {
                        // The value is an OCTET STRING containing 6 bytes
                        if let BerObjectContent::OctetString(fmspc_bytes) = &inner[1].content {
                            if fmspc_bytes.len() == 6 {
                                return Ok(hex::encode(fmspc_bytes));
                            }
                        }
                    }
                }
            }
        }
    }

    Err(AttestationError::CertChainError(
        "FMSPC OID not found in SGX extension".into(),
    ))
}

/// Intel PCS v4 TCB Info JSON structure (subset needed for evaluation).
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TcbInfoWrapper {
    tcb_info: TcbInfoJson,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TcbInfoJson {
    tcb_levels: Vec<TcbLevelJson>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TcbLevelJson {
    tcb: TcbComponentsJson,
    tcb_status: String,
    #[serde(rename = "advisoryIDs", default)]
    advisory_ids: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TcbComponentsJson {
    #[serde(default)]
    sgxtcbcomponents: Vec<SvnComponent>,
    pcesvn: u16,
    #[serde(default)]
    tdxtcbcomponents: Option<Vec<SvnComponent>>,
}

#[derive(Debug, serde::Deserialize)]
struct SvnComponent {
    svn: u8,
}

/// Extract SGX TCB component SVNs from the PCK cert's SGX extensions.
///
/// The PCK certificate contains 16 TCB component SVNs under OID
/// 1.2.840.113741.1.13.1.2.{1..16} and a PCESVN under 1.2.840.113741.1.13.1.2.17.
fn extract_pck_tcb_components(pem_data: &[u8]) -> Result<([u8; 16], u16)> {
    let pem_str = std::str::from_utf8(pem_data).map_err(|e| {
        AttestationError::CertChainError(format!("PEM not UTF-8: {}", e))
    })?;

    let der_certs = split_pem_to_der(pem_str)?;
    if der_certs.is_empty() {
        return Err(AttestationError::CertChainError(
            "no certificates found".into(),
        ));
    }

    let (_, cert) = X509Certificate::from_der(&der_certs[0]).map_err(|e| {
        AttestationError::CertChainError(format!("PCK leaf x509 parse: {}", e))
    })?;

    let sgx_ext_oid = x509_parser::oid_registry::Oid::from(SGX_EXTENSIONS_OID)
        .expect("SGX_EXTENSIONS_OID is valid");
    let tcb_oid = x509_parser::oid_registry::Oid::from(&[1, 2, 840, 113741, 1, 13, 1, 2][..])
        .expect("TCB OID is valid");

    for ext in cert.extensions() {
        if ext.oid == sgx_ext_oid {
            let (_, seq) = parse_der_sequence(ext.value).map_err(|e| {
                AttestationError::CertChainError(format!("SGX extension parse: {}", e))
            })?;

            for item in seq.ref_iter() {
                if let BerObjectContent::Sequence(ref inner) = item.content {
                    if inner.len() >= 2 {
                        if let BerObjectContent::OID(ref oid) = inner[0].content {
                            if *oid == tcb_oid {
                                return parse_tcb_sequence(&inner[1]);
                            }
                        }
                    }
                }
            }
        }
    }

    Err(AttestationError::CertChainError(
        "TCB OID not found in SGX extension".into(),
    ))
}

/// Parse TCB SEQUENCE containing 16 component SVNs and PCESVN.
fn parse_tcb_sequence(
    obj: &x509_parser::der_parser::ber::BerObject,
) -> Result<([u8; 16], u16)> {
    let items = match &obj.content {
        BerObjectContent::Sequence(items) => items,
        _ => {
            return Err(AttestationError::CertChainError(
                "TCB value is not a SEQUENCE".into(),
            ))
        }
    };

    let mut compsvn = [0u8; 16];
    let mut pcesvn: u16 = 0;

    for item in items {
        if let BerObjectContent::Sequence(ref inner) = item.content {
            if inner.len() >= 2 {
                if let BerObjectContent::OID(ref oid) = inner[0].content {
                    let oid_str = oid.to_id_string();
                    // Component SVNs: 1.2.840.113741.1.13.1.2.{1..16}
                    // PCESVN: 1.2.840.113741.1.13.1.2.17
                    if let Some(suffix) = oid_str.strip_prefix("1.2.840.113741.1.13.1.2.") {
                        if let Ok(idx) = suffix.parse::<usize>() {
                            let val = extract_integer_value(&inner[1]);
                            if idx >= 1 && idx <= 16 {
                                compsvn[idx - 1] = val as u8;
                            } else if idx == 17 {
                                pcesvn = val as u16;
                            }
                        }
                    }
                }
            }
        }
    }

    Ok((compsvn, pcesvn))
}

/// Extract an integer value from a BER object (handles INTEGER and OCTET STRING).
fn extract_integer_value(obj: &x509_parser::der_parser::ber::BerObject) -> u64 {
    match &obj.content {
        BerObjectContent::Integer(bytes) => {
            let mut val: u64 = 0;
            for &b in *bytes {
                val = (val << 8) | b as u64;
            }
            val
        }
        BerObjectContent::OctetString(bytes) => {
            let mut val: u64 = 0;
            for &b in *bytes {
                val = (val << 8) | b as u64;
            }
            val
        }
        _ => 0,
    }
}

/// Evaluate TCB status for a TDX quote against Intel TCB Info collateral.
///
/// Matches the quote's TCB SVNs against the TCB levels from Intel PCS,
/// returning the status and any security advisories.
///
/// `tcb_info_json`: raw JSON response from Intel PCS v4 `/tcb` endpoint.
/// `tee_tcb_svn`: 16-byte TEE TCB SVN from the TDX quote body.
/// `pck_pem`: PCK cert chain PEM (for extracting SGX TCB components).
pub fn evaluate_tcb_status(
    tcb_info_json: &[u8],
    tee_tcb_svn: &[u8; 16],
    pck_pem: &[u8],
) -> Result<DcapVerificationStatus> {
    let wrapper: TcbInfoWrapper = serde_json::from_slice(tcb_info_json).map_err(|e| {
        AttestationError::CertChainError(format!("TCB Info JSON parse: {}", e))
    })?;

    let (pck_compsvn, pck_pcesvn) = extract_pck_tcb_components(pck_pem)?;
    let fmspc = extract_fmspc_from_pck(pck_pem)?;

    // Find the first matching TCB level where all SGX platform SVNs >= level SVNs
    // and PCESVN >= level PCESVN
    let mut sgx_match_idx = None;
    for (i, level) in wrapper.tcb_info.tcb_levels.iter().enumerate() {
        let sgx_comps: Vec<u8> = level.tcb.sgxtcbcomponents.iter().map(|c| c.svn).collect();
        if sgx_comps.len() < 16 {
            continue;
        }

        let sgx_match = pck_compsvn
            .iter()
            .zip(sgx_comps.iter())
            .all(|(&pck, &lvl)| pck >= lvl)
            && pck_pcesvn >= level.tcb.pcesvn;

        if sgx_match {
            sgx_match_idx = Some(i);
            break;
        }
    }

    let sgx_idx = sgx_match_idx.ok_or_else(|| {
        AttestationError::TcbMismatch("no matching SGX TCB level found".into())
    })?;

    // Now find matching TDX TCB level starting from the SGX match
    for level in &wrapper.tcb_info.tcb_levels[sgx_idx..] {
        if let Some(ref tdx_comps) = level.tcb.tdxtcbcomponents {
            let tdx_svns: Vec<u8> = tdx_comps.iter().map(|c| c.svn).collect();
            if tdx_svns.len() < 16 {
                continue;
            }

            let tdx_match = tdx_svns
                .iter()
                .zip(tee_tcb_svn.iter())
                .all(|(&lvl, &svn)| lvl <= svn);

            if tdx_match {
                let tcb_status = parse_tcb_status(&level.tcb_status)?;
                return Ok(DcapVerificationStatus {
                    tcb_status,
                    fmspc,
                    advisory_ids: level.advisory_ids.clone(),
                });
            }
        }
    }

    Err(AttestationError::TcbMismatch(
        "no matching TDX TCB level found".into(),
    ))
}

/// Parse a TCB status string from Intel PCS into our enum.
fn parse_tcb_status(s: &str) -> Result<TdxTcbStatus> {
    match s {
        "UpToDate" => Ok(TdxTcbStatus::UpToDate),
        "SWHardeningNeeded" => Ok(TdxTcbStatus::SWHardeningNeeded),
        "ConfigurationNeeded" => Ok(TdxTcbStatus::ConfigurationNeeded),
        "ConfigurationAndSWHardeningNeeded" => {
            Ok(TdxTcbStatus::ConfigurationAndSWHardeningNeeded)
        }
        "OutOfDate" => Ok(TdxTcbStatus::OutOfDate),
        "OutOfDateConfigurationNeeded" => Ok(TdxTcbStatus::OutOfDateConfigurationNeeded),
        "Revoked" => Ok(TdxTcbStatus::Revoked),
        _ => Err(AttestationError::TcbMismatch(format!(
            "unknown TCB status: {}",
            s
        ))),
    }
}

/// Check whether the PCK leaf certificate has been revoked by a CRL.
///
/// `pck_pem`: PCK cert chain PEM data.
/// `crl_der`: DER-encoded CRL (from Intel PCS PCK CRL endpoint).
pub fn check_cert_revocation(pck_pem: &[u8], crl_der: &[u8]) -> Result<()> {
    let pem_str = std::str::from_utf8(pck_pem).map_err(|e| {
        AttestationError::CertChainError(format!("PEM not UTF-8: {}", e))
    })?;

    let der_certs = split_pem_to_der(pem_str)?;
    if der_certs.is_empty() {
        return Err(AttestationError::CertChainError(
            "no certificates found".into(),
        ));
    }

    // Parse the leaf cert to get its serial number
    let (_, leaf_cert) = X509Certificate::from_der(&der_certs[0]).map_err(|e| {
        AttestationError::CertChainError(format!("PCK leaf parse: {}", e))
    })?;
    let leaf_serial = leaf_cert.raw_serial();

    // Parse the CRL
    let (_, crl) = CertificateRevocationList::from_der(crl_der).map_err(|e| {
        AttestationError::CertChainError(format!("CRL DER parse: {}", e))
    })?;

    // Check if leaf serial is in the revoked list
    for revoked in crl.iter_revoked_certificates() {
        if revoked.raw_serial() == leaf_serial {
            return Err(AttestationError::CertChainError(
                "PCK certificate has been revoked".into(),
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const V4_QUOTE: &[u8] = include_bytes!("../../../test_data/tdx_quote_4.dat");
    const V5_QUOTE: &[u8] = include_bytes!("../../../test_data/tdx_quote_5.dat");

    fn body_end_v4() -> usize {
        QUOTE_HEADER_SIZE + REPORT_BODY_SIZE
    }

    fn body_end_v5() -> usize {
        let body_size = V5_QUOTE
            .pread_with::<u32>(QUOTE_HEADER_SIZE + 2, scroll::LE)
            .unwrap() as usize;
        QUOTE_HEADER_SIZE + 6 + body_size
    }

    #[test]
    fn test_parse_auth_data_v4() {
        let body_end = body_end_v4();
        let auth = parse_auth_data(V4_QUOTE, body_end).expect("should parse v4 auth data");
        assert_eq!(auth.attestation_pub_key.len(), 64);
        assert_eq!(auth.qe_report_body.len(), QE_REPORT_BODY_SIZE);
        assert_eq!(auth.qe_report_signature.len(), 64);
        assert!(!auth.pck_cert_chain_pem.is_empty());
    }

    #[test]
    fn test_parse_auth_data_v5() {
        let body_end = body_end_v5();
        let auth = parse_auth_data(V5_QUOTE, body_end).expect("should parse v5 auth data");
        assert_eq!(auth.attestation_pub_key.len(), 64);
        assert_eq!(auth.qe_report_body.len(), QE_REPORT_BODY_SIZE);
        assert_eq!(auth.qe_report_signature.len(), 64);
        assert!(!auth.pck_cert_chain_pem.is_empty());
    }

    #[test]
    fn test_qe_report_binding_v4() {
        let body_end = body_end_v4();
        let auth = parse_auth_data(V4_QUOTE, body_end).unwrap();
        assert!(
            verify_qe_report_binding(&auth).is_ok(),
            "v4 QE report binding should pass"
        );
    }

    #[test]
    fn test_qe_report_binding_v5() {
        let body_end = body_end_v5();
        let auth = parse_auth_data(V5_QUOTE, body_end).unwrap();
        assert!(
            verify_qe_report_binding(&auth).is_ok(),
            "v5 QE report binding should pass"
        );
    }

    #[test]
    fn test_pck_cert_chain_validation_v4() {
        let body_end = body_end_v4();
        let auth = parse_auth_data(V4_QUOTE, body_end).unwrap();
        let result = verify_pck_cert_chain(auth.pck_cert_chain_pem);
        assert!(
            result.is_ok(),
            "v4 PCK cert chain should validate: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_qe_report_signature_v4() {
        let body_end = body_end_v4();
        let auth = parse_auth_data(V4_QUOTE, body_end).unwrap();
        let pck_key = verify_pck_cert_chain(auth.pck_cert_chain_pem).unwrap();
        let result = verify_qe_report_signature(&auth, &pck_key);
        assert!(
            result.is_ok(),
            "v4 QE report sig should verify: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_full_dcap_verification_v4() {
        let body_end = body_end_v4();
        let auth = parse_auth_data(V4_QUOTE, body_end).unwrap();
        let pck_key = verify_pck_cert_chain(auth.pck_cert_chain_pem).unwrap();
        verify_qe_report_signature(&auth, &pck_key).unwrap();
        verify_qe_report_binding(&auth).unwrap();
    }

    #[test]
    fn test_full_dcap_verification_v5() {
        let body_end = body_end_v5();
        let auth = parse_auth_data(V5_QUOTE, body_end).unwrap();
        let pck_key = verify_pck_cert_chain(auth.pck_cert_chain_pem).unwrap();
        verify_qe_report_signature(&auth, &pck_key).unwrap();
        verify_qe_report_binding(&auth).unwrap();
    }

    #[test]
    fn test_tampered_attestation_key_fails() {
        let mut tampered = V4_QUOTE.to_vec();
        let body_end = body_end_v4();
        // Attestation key starts at body_end + 4 + 64
        let key_offset = body_end + 4 + 64;
        tampered[key_offset] ^= 0xFF; // Flip a byte in the attestation key

        let auth = parse_auth_data(&tampered, body_end).unwrap();
        // QE binding should fail since we changed the key
        assert!(
            verify_qe_report_binding(&auth).is_err(),
            "tampered attestation key should fail QE binding"
        );
    }

    #[test]
    fn test_tampered_qe_signature_fails() {
        let mut tampered = V4_QUOTE.to_vec();
        let body_end = body_end_v4();
        let auth_orig = parse_auth_data(V4_QUOTE, body_end).unwrap();
        let pck_key = verify_pck_cert_chain(auth_orig.pck_cert_chain_pem).unwrap();

        // QE report signature is inside the cert data, after the QE report body
        // Find the cert data start: body_end + 4 + 64 + 64 + 6
        let cert_data_start = body_end + 4 + 64 + 64 + 6;
        // QE sig is at cert_data_start + 384
        let qe_sig_offset = cert_data_start + QE_REPORT_BODY_SIZE;
        tampered[qe_sig_offset] ^= 0xFF;

        let auth = parse_auth_data(&tampered, body_end).unwrap();
        assert!(
            verify_qe_report_signature(&auth, &pck_key).is_err(),
            "tampered QE signature should fail verification"
        );
    }

    #[test]
    fn test_compute_body_end_v4() {
        let end = compute_body_end(V4_QUOTE, QuoteVersion::V4).unwrap();
        assert_eq!(end, QUOTE_HEADER_SIZE + REPORT_BODY_SIZE);
    }

    #[test]
    fn test_compute_body_end_v5() {
        let end = compute_body_end(V5_QUOTE, QuoteVersion::V5Tdx15).unwrap();
        assert_eq!(end, body_end_v5());
    }

    // --- Phase 2 tests ---

    #[test]
    fn test_extract_fmspc_from_pck_v4() {
        let body_end = body_end_v4();
        let auth = parse_auth_data(V4_QUOTE, body_end).unwrap();
        let result = extract_fmspc_from_pck(auth.pck_cert_chain_pem);
        assert!(
            result.is_ok(),
            "should extract FMSPC from v4 PCK cert: {:?}",
            result.err()
        );
        let fmspc = result.unwrap();
        // FMSPC is 6 bytes = 12 hex chars
        assert_eq!(fmspc.len(), 12, "FMSPC should be 12 hex chars");
    }

    #[test]
    fn test_extract_fmspc_from_pck_v5() {
        let body_end = body_end_v5();
        let auth = parse_auth_data(V5_QUOTE, body_end).unwrap();
        let result = extract_fmspc_from_pck(auth.pck_cert_chain_pem);
        assert!(
            result.is_ok(),
            "should extract FMSPC from v5 PCK cert: {:?}",
            result.err()
        );
        let fmspc = result.unwrap();
        assert_eq!(fmspc.len(), 12);
    }

    #[test]
    fn test_extract_pck_tcb_components_v4() {
        let body_end = body_end_v4();
        let auth = parse_auth_data(V4_QUOTE, body_end).unwrap();
        let result = extract_pck_tcb_components(auth.pck_cert_chain_pem);
        assert!(
            result.is_ok(),
            "should extract PCK TCB components: {:?}",
            result.err()
        );
        let (compsvn, pcesvn) = result.unwrap();
        // At least some components should be non-zero in a real cert
        assert!(
            compsvn.iter().any(|&v| v != 0) || pcesvn != 0,
            "TCB components should not all be zero"
        );
    }

    #[test]
    fn test_parse_tcb_status_strings() {
        use crate::types::TdxTcbStatus;
        assert_eq!(parse_tcb_status("UpToDate").unwrap(), TdxTcbStatus::UpToDate);
        assert_eq!(
            parse_tcb_status("SWHardeningNeeded").unwrap(),
            TdxTcbStatus::SWHardeningNeeded
        );
        assert_eq!(
            parse_tcb_status("ConfigurationNeeded").unwrap(),
            TdxTcbStatus::ConfigurationNeeded
        );
        assert_eq!(
            parse_tcb_status("OutOfDate").unwrap(),
            TdxTcbStatus::OutOfDate
        );
        assert_eq!(parse_tcb_status("Revoked").unwrap(), TdxTcbStatus::Revoked);
        assert!(parse_tcb_status("InvalidStatus").is_err());
    }

    #[test]
    fn test_check_cert_revocation_empty_crl() {
        // Build a minimal valid empty CRL (no revoked certs)
        // Use the v4 PCK cert chain and a CRL that doesn't revoke it
        let body_end = body_end_v4();
        let auth = parse_auth_data(V4_QUOTE, body_end).unwrap();

        // We can't easily construct a valid DER CRL in a unit test without
        // the issuer's private key, so just verify the function handles
        // parse errors gracefully
        let bogus_crl = vec![0x30, 0x00]; // minimal empty SEQUENCE
        let result = check_cert_revocation(auth.pck_cert_chain_pem, &bogus_crl);
        // Should fail to parse — that's expected
        assert!(result.is_err());
    }
}
