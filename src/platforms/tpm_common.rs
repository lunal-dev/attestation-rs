use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL, Engine};
use rsa::pkcs1v15::VerifyingKey as RsaVerifyingKey;
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use serde::{Deserialize, Serialize};

use crate::error::{AttestationError, Result};

// --- HCL report parsing ---

/// HCL report header magic: "HCLA".
const HCL_MAGIC: [u8; 4] = *b"HCLA";

/// Offset of the TEE report within the HCL report.
const HCL_TEE_REPORT_OFFSET: usize = 0x20;

/// Size of the TEE report area (both SNP and TDX use 1184 bytes).
const HCL_TEE_REPORT_SIZE: usize = 1184;

/// Size of the var_data header after the TEE report (5 × u32 LE).
const HCL_VARDATA_HEADER_SIZE: usize = 20;

/// HCL report type: AMD SEV-SNP.
pub const HCL_REPORT_TYPE_SNP: u32 = 2;

/// HCL report type: Intel TDX.
pub const HCL_REPORT_TYPE_TDX: u32 = 4;

/// Parsed HCL report data.
pub struct HclReportData {
    /// Raw TEE report bytes (1184 bytes).
    pub tee_report: Vec<u8>,
    /// Report type (2=SNP, 4=TDX).
    pub report_type: u32,
    /// Null-trimmed var_data content (JSON with JWK keys).
    pub var_data: Vec<u8>,
}

/// Parse an HCL report blob into its components.
///
/// The HCL report structure:
/// - Bytes 0x00..0x1F: Header (starts with "HCLA" magic)
/// - Bytes 0x20..0x4BF: TEE report (1184 bytes, SNP or TDX)
/// - Bytes 0x4C0..0x4D3: var_data header (20 bytes, 5 × LE u32)
///   - total_remaining, count, report_type, version, content_length
/// - Bytes 0x4D4..end: var_data content (JSON with JWK keys, null-padded)
pub fn parse_hcl_report(hcl_report: &[u8]) -> Result<HclReportData> {
    let tee_report_end = HCL_TEE_REPORT_OFFSET + HCL_TEE_REPORT_SIZE;
    let content_start = tee_report_end + HCL_VARDATA_HEADER_SIZE;

    if hcl_report.len() < content_start {
        return Err(AttestationError::QuoteParseFailed(format!(
            "HCL report too short: {} < {}",
            hcl_report.len(),
            content_start
        )));
    }

    if hcl_report[..4] != HCL_MAGIC {
        return Err(AttestationError::QuoteParseFailed(format!(
            "invalid HCL magic: {:02X}{:02X}{:02X}{:02X}",
            hcl_report[0], hcl_report[1], hcl_report[2], hcl_report[3]
        )));
    }

    let tee_report = hcl_report[HCL_TEE_REPORT_OFFSET..tee_report_end].to_vec();

    // Parse var_data header (all fields are little-endian u32)
    let header = &hcl_report[tee_report_end..content_start];
    let report_type = u32::from_le_bytes(header[8..12].try_into().unwrap());

    // Extract content and trim trailing nulls
    let content = &hcl_report[content_start..];
    let trimmed_len = content
        .iter()
        .rposition(|&b| b != 0)
        .map_or(0, |i| i + 1);

    Ok(HclReportData {
        tee_report,
        report_type,
        var_data: content[..trimmed_len].to_vec(),
    })
}

/// Extract the AK public key (RSA modulus and exponent) from HCL var_data JSON.
///
/// The var_data contains JSON with a "keys" array. The AK public key
/// has `kid="HCLAkPub"` and `kty="RSA"`, with base64url-encoded `n`
/// (modulus) and `e` (exponent) fields.
pub fn extract_ak_pub_from_jwk_json(json_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let json: serde_json::Value = serde_json::from_slice(json_bytes)
        .map_err(|e| AttestationError::QuoteParseFailed(format!("HCL var_data JSON: {}", e)))?;

    let keys = json["keys"].as_array().ok_or_else(|| {
        AttestationError::QuoteParseFailed("HCL var_data JSON missing 'keys' array".to_string())
    })?;

    for key in keys {
        let kid = key["kid"].as_str().unwrap_or("");
        let kty = key["kty"].as_str().unwrap_or("");

        if kid == "HCLAkPub" && kty == "RSA" {
            let n_b64 = key["n"].as_str().ok_or_else(|| {
                AttestationError::QuoteParseFailed("HCLAkPub missing 'n' field".to_string())
            })?;
            let e_b64 = key["e"].as_str().ok_or_else(|| {
                AttestationError::QuoteParseFailed("HCLAkPub missing 'e' field".to_string())
            })?;

            let modulus = BASE64URL.decode(n_b64).map_err(|e| {
                AttestationError::QuoteParseFailed(format!("HCLAkPub 'n' base64: {}", e))
            })?;
            let exponent = BASE64URL.decode(e_b64).map_err(|e| {
                AttestationError::QuoteParseFailed(format!("HCLAkPub 'e' base64: {}", e))
            })?;

            return Ok((modulus, exponent));
        }
    }

    Err(AttestationError::QuoteParseFailed(
        "HCL var_data JSON does not contain HCLAkPub RSA key".to_string(),
    ))
}

/// TPM quote data, shared between Azure SNP and Azure TDX platforms.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmQuote {
    /// TPM signature bytes (hex encoded).
    pub signature: String,
    /// TPM Attest message bytes (hex encoded).
    pub message: String,
    /// PCR values (24 entries, each hex encoded SHA-256 digest).
    pub pcrs: Vec<String>,
}

/// Verify TPM quote signature using the AK public key from HCL var_data.
///
/// The Azure vTPM uses RSA 2048 with RSASSA-PKCS1-v1.5 and SHA-256 for
/// its Attestation Key (AK). The AK public key is embedded in the HCL
/// report's variable data, either as JWK JSON (real Azure format) or
/// as a TPM2B_PUBLIC structure (synthetic test data).
pub fn verify_tpm_signature(
    signature: &[u8],
    message: &[u8],
    var_data: &[u8],
) -> Result<bool> {
    // Extract the RSA public key: try JWK JSON first, fall back to TPM2B_PUBLIC
    let (modulus, exponent) = extract_ak_pub_from_jwk_json(var_data)
        .or_else(|_| extract_ak_pub_from_var_data(var_data))?;

    let n = rsa::BigUint::from_bytes_be(&modulus);
    let e = rsa::BigUint::from_bytes_be(&exponent);

    let public_key = RsaPublicKey::new(n, e).map_err(|e| {
        AttestationError::SignatureVerificationFailed(format!("construct RSA key: {}", e))
    })?;

    let verifying_key = RsaVerifyingKey::<sha2::Sha256>::new(public_key);

    let sig = rsa::pkcs1v15::Signature::try_from(signature).map_err(|e| {
        AttestationError::SignatureVerificationFailed(format!("parse RSA sig: {}", e))
    })?;

    match verifying_key.verify(message, &sig) {
        Ok(()) => Ok(true),
        Err(e) => Err(AttestationError::SignatureVerificationFailed(format!(
            "TPM RSA PKCS1v15 SHA-256: {}",
            e
        ))),
    }
}

/// Extract the AK public key (RSA modulus and exponent) from HCL var_data.
///
/// The var_data contains a TPM2B_PUBLIC structure. For Azure vTPM, the
/// key is RSA 2048 with exponent 65537.
///
/// TPM2B_PUBLIC layout:
/// - size: 2 bytes (BE)
/// - TPMT_PUBLIC:
///   - type: 2 bytes (BE) - TPM_ALG_RSA = 0x0001
///   - nameAlg: 2 bytes (BE) - TPM_ALG_SHA256 = 0x000B
///   - objectAttributes: 4 bytes
///   - authPolicy: 2 bytes size + data
///   - parameters (TPMS_RSA_PARMS):
///     - symmetric: 2 bytes (TPM_ALG_NULL = 0x0010)
///     - scheme: 2 bytes
///     - keyBits: 2 bytes (BE)
///     - exponent: 4 bytes (0 means 65537)
///   - unique (TPM2B_PUBLIC_KEY_RSA):
///     - size: 2 bytes
///     - modulus: size bytes
pub(crate) fn extract_ak_pub_from_var_data(var_data: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if var_data.len() < 14 {
        return Err(AttestationError::QuoteParseFailed(
            "var_data too short for TPM2B_PUBLIC".to_string(),
        ));
    }

    let mut offset = 0;

    // TPM2B_PUBLIC.size
    let _pub_size = u16::from_be_bytes(var_data[offset..offset + 2].try_into().unwrap());
    offset += 2;

    // TPMT_PUBLIC.type
    let alg_type = u16::from_be_bytes(var_data[offset..offset + 2].try_into().unwrap());
    offset += 2;

    if alg_type != 0x0001 {
        // TPM_ALG_RSA = 0x0001
        return Err(AttestationError::SignatureVerificationFailed(format!(
            "AK key type 0x{:04x} is not RSA (expected 0x0001)",
            alg_type
        )));
    }

    // TPMT_PUBLIC.nameAlg
    let _name_alg = u16::from_be_bytes(var_data[offset..offset + 2].try_into().unwrap());
    offset += 2;

    // objectAttributes
    offset += 4;

    // authPolicy (TPM2B_DIGEST): 2-byte size + data
    if offset + 2 > var_data.len() {
        return Err(AttestationError::QuoteParseFailed(
            "var_data truncated at authPolicy".to_string(),
        ));
    }
    let auth_size = u16::from_be_bytes(var_data[offset..offset + 2].try_into().unwrap()) as usize;
    offset += 2 + auth_size;

    // TPMS_RSA_PARMS
    if offset + 10 > var_data.len() {
        return Err(AttestationError::QuoteParseFailed(
            "var_data truncated at RSA params".to_string(),
        ));
    }

    // symmetric (TPM_ALG_ID)
    let sym_alg = u16::from_be_bytes(var_data[offset..offset + 2].try_into().unwrap());
    offset += 2;

    // If symmetric is not NULL, skip the symmetric definition
    if sym_alg != 0x0010 {
        // TPM_ALG_NULL
        // Skip symmetric algorithm, key bits, and mode (2 + 2 + 2 = 6 bytes)
        offset += 6;
    }

    // scheme (TPMT_RSA_SCHEME): algorithm (2 bytes) + optional hash (2 bytes)
    let scheme_alg = u16::from_be_bytes(var_data[offset..offset + 2].try_into().unwrap());
    offset += 2;
    if scheme_alg != 0x0010 {
        // Not TPM_ALG_NULL, skip hash algorithm
        offset += 2;
    }

    // keyBits
    if offset + 6 > var_data.len() {
        return Err(AttestationError::QuoteParseFailed(
            "var_data truncated at keyBits".to_string(),
        ));
    }
    let _key_bits = u16::from_be_bytes(var_data[offset..offset + 2].try_into().unwrap());
    offset += 2;

    // exponent (4 bytes, 0 means default 65537)
    let exp_val = u32::from_be_bytes(var_data[offset..offset + 4].try_into().unwrap());
    offset += 4;

    let exponent = if exp_val == 0 {
        vec![0x01, 0x00, 0x01] // 65537
    } else {
        exp_val.to_be_bytes().to_vec()
    };

    // TPM2B_PUBLIC_KEY_RSA (unique): 2-byte size + modulus
    if offset + 2 > var_data.len() {
        return Err(AttestationError::QuoteParseFailed(
            "var_data truncated at unique".to_string(),
        ));
    }
    let mod_size =
        u16::from_be_bytes(var_data[offset..offset + 2].try_into().unwrap()) as usize;
    offset += 2;

    if offset + mod_size > var_data.len() {
        return Err(AttestationError::QuoteParseFailed(format!(
            "var_data truncated at modulus: need {} bytes at offset {}, have {}",
            mod_size,
            offset,
            var_data.len()
        )));
    }

    let modulus = var_data[offset..offset + mod_size].to_vec();

    Ok((modulus, exponent))
}

/// Verify TPM nonce matches expected report_data.
pub fn verify_tpm_nonce(message: &[u8], expected: &[u8]) -> Result<bool> {
    // TPM Attest structure (TPMS_ATTEST):
    // - magic (4 bytes): 0xFF544347 ("TCG\xFF")
    // - type (2 bytes): TPM_ST_ATTEST_QUOTE
    // - qualifiedSigner (variable)
    // - extraData (variable) <-- this contains the nonce
    // - clockInfo (17 bytes)
    // - firmwareVersion (8 bytes)
    // - attested (variable)

    if message.len() < 10 {
        return Err(AttestationError::QuoteParseFailed(
            "TPM Attest message too short".to_string(),
        ));
    }

    // Check magic
    let magic = u32::from_be_bytes(message[0..4].try_into().unwrap());
    if magic != 0xFF544347 {
        return Err(AttestationError::QuoteParseFailed(format!(
            "invalid TPM Attest magic: 0x{:08X}",
            magic
        )));
    }

    // Skip type (2 bytes), then parse qualifiedSigner (TPM2B_NAME)
    let mut offset = 6;

    // qualifiedSigner: 2-byte size + data
    if message.len() < offset + 2 {
        return Err(AttestationError::QuoteParseFailed(
            "TPM Attest truncated at qualifiedSigner".to_string(),
        ));
    }
    let signer_size =
        u16::from_be_bytes(message[offset..offset + 2].try_into().unwrap()) as usize;
    offset += 2 + signer_size;

    // extraData: 2-byte size + data (this is the nonce)
    if message.len() < offset + 2 {
        return Err(AttestationError::QuoteParseFailed(
            "TPM Attest truncated at extraData".to_string(),
        ));
    }
    let nonce_size =
        u16::from_be_bytes(message[offset..offset + 2].try_into().unwrap()) as usize;
    offset += 2;

    if message.len() < offset + nonce_size {
        return Err(AttestationError::QuoteParseFailed(
            "TPM Attest truncated at nonce data".to_string(),
        ));
    }

    let nonce = &message[offset..offset + nonce_size];

    // Compare nonce with expected report_data (hash comparison)
    // The nonce is typically the SHA-256 of the report_data
    let expected_hash = crate::utils::sha256(expected);

    if nonce.len() == expected_hash.len() {
        Ok(crate::utils::constant_time_eq(nonce, &expected_hash))
    } else if nonce.len() == expected.len() {
        Ok(crate::utils::constant_time_eq(nonce, expected))
    } else {
        Ok(false)
    }
}

/// Verify TPM PCR digest integrity.
///
/// Parses the PCR selection and digest from the TPMS_ATTEST message,
/// then verifies that the digest matches the hash of the selected
/// PCR values.
pub fn verify_tpm_pcrs(message: &[u8], pcrs: &[Vec<u8>]) -> Result<()> {
    if pcrs.is_empty() {
        return Err(AttestationError::QuoteParseFailed(
            "no PCR values in TPM quote".to_string(),
        ));
    }

    for (i, pcr) in pcrs.iter().enumerate() {
        if pcr.len() != 32 {
            return Err(AttestationError::QuoteParseFailed(format!(
                "PCR[{}] has unexpected size: {} (expected 32)",
                i,
                pcr.len()
            )));
        }
    }

    // Parse the TPMS_ATTEST to extract the PCR digest from the attested data.
    // The TPMS_ATTEST layout after the fields we parsed in verify_tpm_nonce:
    // - magic (4) + type (2) + qualifiedSigner (var) + extraData (var) +
    //   clockInfo (17) + firmwareVersion (8) + attested (TPMS_QUOTE_INFO)
    //
    // TPMS_QUOTE_INFO:
    //   - pcrSelect (TPML_PCR_SELECTION): count(4) + selections(count * var)
    //   - pcrDigest (TPM2B_DIGEST): size(2) + data(size)
    //
    // Rather than fully re-parse, extract the digest from the end of the attest
    // and verify by hashing the concatenation of all selected PCR values.

    let (selected_pcrs, expected_digest) = parse_quote_info(message)?;

    // Concatenate all selected PCR values and hash them
    let mut pcr_concat = Vec::new();
    for &idx in &selected_pcrs {
        if idx >= pcrs.len() {
            return Err(AttestationError::QuoteParseFailed(format!(
                "PCR selection references PCR[{}] but only {} PCRs available",
                idx,
                pcrs.len()
            )));
        }
        pcr_concat.extend_from_slice(&pcrs[idx]);
    }

    let computed_digest = crate::utils::sha256(&pcr_concat);

    if !crate::utils::constant_time_eq(&computed_digest, &expected_digest) {
        return Err(AttestationError::QuoteParseFailed(
            "PCR digest in TPM quote does not match hash of PCR values".to_string(),
        ));
    }

    Ok(())
}

/// Parse TPMS_QUOTE_INFO from a TPMS_ATTEST message to extract the PCR
/// selection bitmap and the expected PCR digest.
fn parse_quote_info(message: &[u8]) -> Result<(Vec<usize>, Vec<u8>)> {
    if message.len() < 10 {
        return Err(AttestationError::QuoteParseFailed(
            "TPMS_ATTEST too short".to_string(),
        ));
    }

    // Skip: magic(4) + type(2)
    let mut offset = 6;

    // qualifiedSigner (TPM2B_NAME): size(2) + data
    if offset + 2 > message.len() {
        return Err(AttestationError::QuoteParseFailed(
            "truncated at qualifiedSigner".to_string(),
        ));
    }
    let signer_size =
        u16::from_be_bytes(message[offset..offset + 2].try_into().unwrap()) as usize;
    offset += 2 + signer_size;

    // extraData (TPM2B_DATA): size(2) + data
    if offset + 2 > message.len() {
        return Err(AttestationError::QuoteParseFailed(
            "truncated at extraData".to_string(),
        ));
    }
    let extra_size =
        u16::from_be_bytes(message[offset..offset + 2].try_into().unwrap()) as usize;
    offset += 2 + extra_size;

    // clockInfo (TPMS_CLOCK_INFO): clock(8) + resetCount(4) + restartCount(4) + safe(1) = 17
    offset += 17;

    // firmwareVersion: 8 bytes
    offset += 8;

    // Now we're at the TPMS_QUOTE_INFO (attested data)
    // TPML_PCR_SELECTION: count(4) + selections
    if offset + 4 > message.len() {
        return Err(AttestationError::QuoteParseFailed(
            "truncated at PCR selection count".to_string(),
        ));
    }
    let pcr_selection_count =
        u32::from_be_bytes(message[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;

    let mut selected_pcrs = Vec::new();

    for _ in 0..pcr_selection_count {
        // TPMS_PCR_SELECTION: hash(2) + sizeofSelect(1) + pcrSelect(sizeofSelect)
        if offset + 3 > message.len() {
            return Err(AttestationError::QuoteParseFailed(
                "truncated at PCR selection entry".to_string(),
            ));
        }
        let _hash_alg = u16::from_be_bytes(message[offset..offset + 2].try_into().unwrap());
        offset += 2;

        let select_size = message[offset] as usize;
        offset += 1;

        if offset + select_size > message.len() {
            return Err(AttestationError::QuoteParseFailed(
                "truncated at PCR selection bitmap".to_string(),
            ));
        }

        // Parse the bitmap to find selected PCR indices
        for byte_idx in 0..select_size {
            let byte = message[offset + byte_idx];
            for bit_idx in 0..8u8 {
                if byte & (1 << bit_idx) != 0 {
                    selected_pcrs.push(byte_idx * 8 + bit_idx as usize);
                }
            }
        }
        offset += select_size;
    }

    // TPM2B_DIGEST (pcrDigest): size(2) + data
    if offset + 2 > message.len() {
        return Err(AttestationError::QuoteParseFailed(
            "truncated at PCR digest".to_string(),
        ));
    }
    let digest_size =
        u16::from_be_bytes(message[offset..offset + 2].try_into().unwrap()) as usize;
    offset += 2;

    if offset + digest_size > message.len() {
        return Err(AttestationError::QuoteParseFailed(
            "truncated at PCR digest data".to_string(),
        ));
    }

    let digest = message[offset..offset + digest_size].to_vec();

    Ok((selected_pcrs, digest))
}

/// Parse TPM quote from evidence, returning decoded (sig, msg, pcrs).
pub fn decode_tpm_quote(quote: &TpmQuote) -> Result<(Vec<u8>, Vec<u8>, Vec<Vec<u8>>)> {
    let sig = hex::decode(&quote.signature)
        .map_err(|e| AttestationError::EvidenceDeserialize(format!("TPM sig hex: {}", e)))?;
    let msg = hex::decode(&quote.message)
        .map_err(|e| AttestationError::EvidenceDeserialize(format!("TPM msg hex: {}", e)))?;
    let pcrs: Vec<Vec<u8>> = quote
        .pcrs
        .iter()
        .map(|p| {
            hex::decode(p)
                .map_err(|e| AttestationError::EvidenceDeserialize(format!("PCR hex: {}", e)))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((sig, msg, pcrs))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Helper: build a synthetic TPMS_ATTEST message ---
    fn build_tpms_attest(nonce: &[u8], pcr_selection: &[u8], pcr_digest: &[u8]) -> Vec<u8> {
        let mut msg = Vec::new();
        // magic: 0xFF544347
        msg.extend_from_slice(&[0xFF, 0x54, 0x43, 0x47]);
        // type: TPM_ST_ATTEST_QUOTE = 0x8018
        msg.extend_from_slice(&[0x80, 0x18]);
        // qualifiedSigner: size=0
        msg.extend_from_slice(&[0x00, 0x00]);
        // extraData (nonce): size + data
        msg.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
        msg.extend_from_slice(nonce);
        // clockInfo: clock(8) + resetCount(4) + restartCount(4) + safe(1) = 17 bytes
        msg.extend_from_slice(&[0u8; 17]);
        // firmwareVersion: 8 bytes
        msg.extend_from_slice(&[0u8; 8]);
        // TPML_PCR_SELECTION: count=1
        msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        // TPMS_PCR_SELECTION: hash=SHA256(0x000B), sizeofSelect + bitmap
        msg.extend_from_slice(&[0x00, 0x0B]);
        msg.extend_from_slice(pcr_selection);
        // TPM2B_DIGEST: size + data
        msg.extend_from_slice(&(pcr_digest.len() as u16).to_be_bytes());
        msg.extend_from_slice(pcr_digest);
        msg
    }

    // --- Helper: build a minimal TPM2B_PUBLIC for RSA 2048 ---
    fn build_tpm2b_public_rsa(modulus: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        // Content (after size field)
        let mut content = Vec::new();
        // type: TPM_ALG_RSA = 0x0001
        content.extend_from_slice(&[0x00, 0x01]);
        // nameAlg: TPM_ALG_SHA256 = 0x000B
        content.extend_from_slice(&[0x00, 0x0B]);
        // objectAttributes: 4 bytes
        content.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // authPolicy: size=0
        content.extend_from_slice(&[0x00, 0x00]);
        // symmetric: TPM_ALG_NULL = 0x0010
        content.extend_from_slice(&[0x00, 0x10]);
        // scheme: TPM_ALG_NULL = 0x0010
        content.extend_from_slice(&[0x00, 0x10]);
        // keyBits: 2048 = 0x0800
        content.extend_from_slice(&[0x08, 0x00]);
        // exponent: 0 (default 65537)
        content.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // unique (TPM2B_PUBLIC_KEY_RSA): size + modulus
        content.extend_from_slice(&(modulus.len() as u16).to_be_bytes());
        content.extend_from_slice(modulus);

        // TPM2B_PUBLIC.size
        data.extend_from_slice(&(content.len() as u16).to_be_bytes());
        data.extend_from_slice(&content);
        data
    }

    // --- Nonce tests ---

    #[test]
    fn test_tpm_nonce_parse_bad_magic() {
        let msg = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(verify_tpm_nonce(&msg, b"test").is_err());
    }

    #[test]
    fn test_tpm_nonce_parse_too_short() {
        let msg = vec![0xFF, 0x54, 0x43, 0x47, 0x00];
        assert!(verify_tpm_nonce(&msg, b"test").is_err());
    }

    #[test]
    fn test_tpm_nonce_valid_sha256_match() {
        let report_data = b"hello world";
        let expected_nonce = crate::utils::sha256(report_data);
        let pcr_digest = [0u8; 32];
        // sizeofSelect=3, select all 24 PCRs (0xFF, 0xFF, 0xFF)
        let msg = build_tpms_attest(&expected_nonce, &[3, 0xFF, 0xFF, 0xFF], &pcr_digest);
        let result = verify_tpm_nonce(&msg, report_data).unwrap();
        assert!(result, "nonce should match SHA-256 of report_data");
    }

    #[test]
    fn test_tpm_nonce_mismatch() {
        let nonce = crate::utils::sha256(b"correct data");
        let pcr_digest = [0u8; 32];
        let msg = build_tpms_attest(&nonce, &[3, 0xFF, 0xFF, 0xFF], &pcr_digest);
        let result = verify_tpm_nonce(&msg, b"wrong data").unwrap();
        assert!(!result, "nonce should not match for different data");
    }

    #[test]
    fn test_tpm_nonce_direct_match() {
        // When nonce length != 32 (SHA-256 output) but matches expected length,
        // do direct byte comparison instead of SHA-256 comparison.
        let nonce = b"short_nonce"; // 11 bytes, not 32
        let pcr_digest = [0u8; 32];
        let msg = build_tpms_attest(nonce, &[3, 0xFF, 0xFF, 0xFF], &pcr_digest);
        let result = verify_tpm_nonce(&msg, nonce.as_slice()).unwrap();
        assert!(result, "nonce should match via direct comparison");
    }

    #[test]
    fn test_tpm_nonce_truncated_at_signer() {
        // Valid magic + type, but truncated before qualifiedSigner size
        let msg = vec![0xFF, 0x54, 0x43, 0x47, 0x80, 0x18];
        assert!(verify_tpm_nonce(&msg, b"test").is_err());
    }

    #[test]
    fn test_tpm_nonce_truncated_at_extra_data() {
        let mut msg = vec![0xFF, 0x54, 0x43, 0x47, 0x80, 0x18];
        msg.extend_from_slice(&[0x00, 0x00]); // qualifiedSigner size=0
        // No extraData follows
        assert!(verify_tpm_nonce(&msg, b"test").is_err());
    }

    // --- PCR verification tests ---

    #[test]
    fn test_tpm_pcrs_valid_digest() {
        // Build 24 PCR values (all zeros)
        let pcrs: Vec<Vec<u8>> = (0..24).map(|_| vec![0u8; 32]).collect();

        // Select PCRs 0-7 (first byte = 0xFF)
        let mut pcr_concat = Vec::new();
        for i in 0..8 {
            pcr_concat.extend_from_slice(&pcrs[i]);
        }
        let expected_digest = crate::utils::sha256(&pcr_concat);

        // Build TPMS_ATTEST with sizeofSelect=3, bitmap [0xFF, 0x00, 0x00] (PCRs 0-7)
        let nonce = [0u8; 32];
        let msg = build_tpms_attest(&nonce, &[3, 0xFF, 0x00, 0x00], &expected_digest);

        let result = verify_tpm_pcrs(&msg, &pcrs);
        assert!(result.is_ok(), "valid PCR digest should pass: {:?}", result.err());
    }

    #[test]
    fn test_tpm_pcrs_wrong_digest() {
        let pcrs: Vec<Vec<u8>> = (0..24).map(|_| vec![0u8; 32]).collect();
        let wrong_digest = [0xAA; 32];
        let nonce = [0u8; 32];
        let msg = build_tpms_attest(&nonce, &[3, 0xFF, 0x00, 0x00], &wrong_digest);

        let result = verify_tpm_pcrs(&msg, &pcrs);
        assert!(result.is_err(), "wrong PCR digest should fail");
    }

    #[test]
    fn test_tpm_pcrs_empty() {
        let result = verify_tpm_pcrs(&[], &[]);
        assert!(result.is_err(), "empty PCR list should fail");
    }

    #[test]
    fn test_tpm_pcrs_wrong_size() {
        let pcrs = vec![vec![0u8; 16]]; // Wrong size (should be 32)
        let result = verify_tpm_pcrs(&[0u8; 100], &pcrs);
        assert!(result.is_err(), "PCR with wrong size should fail");
    }

    #[test]
    fn test_tpm_pcrs_single_pcr_selected() {
        // Select only PCR[0]
        let pcrs: Vec<Vec<u8>> = (0..24).map(|i| vec![i as u8; 32]).collect();
        let pcr0_digest = crate::utils::sha256(&pcrs[0]);

        let nonce = [0u8; 32];
        let msg = build_tpms_attest(&nonce, &[3, 0x01, 0x00, 0x00], &pcr0_digest);

        assert!(verify_tpm_pcrs(&msg, &pcrs).is_ok());
    }

    #[test]
    fn test_tpm_pcrs_non_contiguous_selection() {
        // Select PCR 0, 2, 4 (bitmap: 0b00010101 = 0x15)
        let pcrs: Vec<Vec<u8>> = (0..24).map(|i| vec![i as u8; 32]).collect();
        let mut concat = Vec::new();
        concat.extend_from_slice(&pcrs[0]);
        concat.extend_from_slice(&pcrs[2]);
        concat.extend_from_slice(&pcrs[4]);
        let digest = crate::utils::sha256(&concat);

        let nonce = [0u8; 32];
        let msg = build_tpms_attest(&nonce, &[3, 0x15, 0x00, 0x00], &digest);

        assert!(verify_tpm_pcrs(&msg, &pcrs).is_ok());
    }

    // --- TPM2B_PUBLIC / AK extraction tests ---

    #[test]
    fn test_extract_ak_pub_rsa_2048() {
        let modulus = vec![0xAB; 256]; // 2048-bit modulus
        let var_data = build_tpm2b_public_rsa(&modulus);

        let (extracted_mod, extracted_exp) = extract_ak_pub_from_var_data(&var_data).unwrap();
        assert_eq!(extracted_mod, modulus, "modulus should match");
        assert_eq!(extracted_exp, vec![0x01, 0x00, 0x01], "exponent should be 65537");
    }

    #[test]
    fn test_extract_ak_pub_custom_exponent() {
        let mut var_data = Vec::new();
        let mut content = Vec::new();
        content.extend_from_slice(&[0x00, 0x01]); // RSA
        content.extend_from_slice(&[0x00, 0x0B]); // SHA-256
        content.extend_from_slice(&[0x00; 4]); // objectAttributes
        content.extend_from_slice(&[0x00, 0x00]); // authPolicy size=0
        content.extend_from_slice(&[0x00, 0x10]); // symmetric=NULL
        content.extend_from_slice(&[0x00, 0x10]); // scheme=NULL
        content.extend_from_slice(&[0x08, 0x00]); // keyBits=2048
        content.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // exponent=65537 explicit
        let modulus = vec![0xCD; 256];
        content.extend_from_slice(&(modulus.len() as u16).to_be_bytes());
        content.extend_from_slice(&modulus);

        var_data.extend_from_slice(&(content.len() as u16).to_be_bytes());
        var_data.extend_from_slice(&content);

        let (extracted_mod, extracted_exp) = extract_ak_pub_from_var_data(&var_data).unwrap();
        assert_eq!(extracted_mod, modulus);
        // Non-zero exponent is returned as big-endian bytes of the u32
        assert_eq!(extracted_exp, vec![0x00, 0x01, 0x00, 0x01]);
    }

    #[test]
    fn test_extract_ak_pub_too_short() {
        let var_data = vec![0u8; 10]; // Too short for TPM2B_PUBLIC
        assert!(extract_ak_pub_from_var_data(&var_data).is_err());
    }

    #[test]
    fn test_extract_ak_pub_not_rsa() {
        let mut var_data = Vec::new();
        let mut content = Vec::new();
        content.extend_from_slice(&[0x00, 0x23]); // TPM_ALG_ECC (not RSA)
        content.extend_from_slice(&[0x00, 0x0B]); // SHA-256
        content.extend_from_slice(&[0x00; 4]); // objectAttributes
        content.extend_from_slice(&[0x00, 0x00]); // authPolicy size=0
        content.extend_from_slice(&[0x00; 20]); // padding

        var_data.extend_from_slice(&(content.len() as u16).to_be_bytes());
        var_data.extend_from_slice(&content);

        let result = extract_ak_pub_from_var_data(&var_data);
        assert!(result.is_err(), "non-RSA key type should be rejected");
        let err_msg = format!("{:?}", result.err().unwrap());
        assert!(err_msg.contains("not RSA"), "error should mention RSA: {}", err_msg);
    }

    #[test]
    fn test_extract_ak_pub_truncated_at_auth_policy() {
        let mut var_data = Vec::new();
        let mut content = Vec::new();
        content.extend_from_slice(&[0x00, 0x01]); // RSA
        content.extend_from_slice(&[0x00, 0x0B]); // SHA-256
        content.extend_from_slice(&[0x00; 4]); // objectAttributes
        // No authPolicy follows

        var_data.extend_from_slice(&(content.len() as u16).to_be_bytes());
        var_data.extend_from_slice(&content);

        assert!(extract_ak_pub_from_var_data(&var_data).is_err());
    }

    #[test]
    fn test_extract_ak_pub_truncated_at_modulus() {
        let mut var_data = Vec::new();
        let mut content = Vec::new();
        content.extend_from_slice(&[0x00, 0x01]); // RSA
        content.extend_from_slice(&[0x00, 0x0B]); // SHA-256
        content.extend_from_slice(&[0x00; 4]); // objectAttributes
        content.extend_from_slice(&[0x00, 0x00]); // authPolicy size=0
        content.extend_from_slice(&[0x00, 0x10]); // symmetric=NULL
        content.extend_from_slice(&[0x00, 0x10]); // scheme=NULL
        content.extend_from_slice(&[0x08, 0x00]); // keyBits=2048
        content.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // exponent=0
        content.extend_from_slice(&[0x01, 0x00]); // modulus size=256 but no data

        var_data.extend_from_slice(&(content.len() as u16).to_be_bytes());
        var_data.extend_from_slice(&content);

        assert!(extract_ak_pub_from_var_data(&var_data).is_err());
    }

    #[test]
    fn test_extract_ak_pub_with_auth_policy_data() {
        // Test with non-empty authPolicy (32-byte SHA-256 digest)
        let modulus = vec![0xEF; 256];
        let mut var_data = Vec::new();
        let mut content = Vec::new();
        content.extend_from_slice(&[0x00, 0x01]); // RSA
        content.extend_from_slice(&[0x00, 0x0B]); // SHA-256
        content.extend_from_slice(&[0x00; 4]); // objectAttributes
        content.extend_from_slice(&[0x00, 0x20]); // authPolicy size=32
        content.extend_from_slice(&[0xAA; 32]); // authPolicy data
        content.extend_from_slice(&[0x00, 0x10]); // symmetric=NULL
        content.extend_from_slice(&[0x00, 0x10]); // scheme=NULL
        content.extend_from_slice(&[0x08, 0x00]); // keyBits=2048
        content.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // exponent=0
        content.extend_from_slice(&(modulus.len() as u16).to_be_bytes());
        content.extend_from_slice(&modulus);

        var_data.extend_from_slice(&(content.len() as u16).to_be_bytes());
        var_data.extend_from_slice(&content);

        let (extracted_mod, extracted_exp) = extract_ak_pub_from_var_data(&var_data).unwrap();
        assert_eq!(extracted_mod, modulus);
        assert_eq!(extracted_exp, vec![0x01, 0x00, 0x01]);
    }

    // --- decode_tpm_quote tests ---

    #[test]
    fn test_decode_tpm_quote_valid() {
        let quote = TpmQuote {
            signature: "deadbeef".to_string(),
            message: "cafebabe".to_string(),
            pcrs: vec![
                "00".repeat(32),
                "ff".repeat(32),
            ],
        };

        let (sig, msg, pcrs) = decode_tpm_quote(&quote).unwrap();
        assert_eq!(sig, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(msg, vec![0xCA, 0xFE, 0xBA, 0xBE]);
        assert_eq!(pcrs.len(), 2);
        assert_eq!(pcrs[0], vec![0x00; 32]);
        assert_eq!(pcrs[1], vec![0xFF; 32]);
    }

    #[test]
    fn test_decode_tpm_quote_invalid_hex_sig() {
        let quote = TpmQuote {
            signature: "not_hex!".to_string(),
            message: "cafebabe".to_string(),
            pcrs: vec![],
        };
        assert!(decode_tpm_quote(&quote).is_err());
    }

    #[test]
    fn test_decode_tpm_quote_invalid_hex_msg() {
        let quote = TpmQuote {
            signature: "deadbeef".to_string(),
            message: "zzz".to_string(),
            pcrs: vec![],
        };
        assert!(decode_tpm_quote(&quote).is_err());
    }

    #[test]
    fn test_decode_tpm_quote_invalid_hex_pcr() {
        let quote = TpmQuote {
            signature: "deadbeef".to_string(),
            message: "cafebabe".to_string(),
            pcrs: vec!["00".repeat(32), "invalid_hex".to_string()],
        };
        assert!(decode_tpm_quote(&quote).is_err());
    }

    // --- parse_quote_info tests ---

    #[test]
    fn test_parse_quote_info_valid() {
        let digest = [0xBB; 32];
        // Select PCRs 0, 1, 2 (bitmap byte 0 = 0b00000111 = 0x07)
        let msg = build_tpms_attest(&[0u8; 32], &[3, 0x07, 0x00, 0x00], &digest);

        let (selected, extracted_digest) = parse_quote_info(&msg).unwrap();
        assert_eq!(selected, vec![0, 1, 2]);
        assert_eq!(extracted_digest, digest.to_vec());
    }

    #[test]
    fn test_parse_quote_info_high_pcrs() {
        // Select PCRs 16, 17, 18 (byte 2, bits 0,1,2 = 0x07)
        let digest = [0xCC; 32];
        let msg = build_tpms_attest(&[0u8; 32], &[3, 0x00, 0x00, 0x07], &digest);

        let (selected, _) = parse_quote_info(&msg).unwrap();
        assert_eq!(selected, vec![16, 17, 18]);
    }

    #[test]
    fn test_parse_quote_info_all_24_pcrs() {
        let digest = [0xDD; 32];
        let msg = build_tpms_attest(&[0u8; 32], &[3, 0xFF, 0xFF, 0xFF], &digest);

        let (selected, _) = parse_quote_info(&msg).unwrap();
        assert_eq!(selected.len(), 24);
        assert_eq!(selected, (0..24).collect::<Vec<_>>());
    }

    #[test]
    fn test_parse_quote_info_truncated() {
        assert!(parse_quote_info(&[]).is_err());
        assert!(parse_quote_info(&[0xFF, 0x54, 0x43, 0x47, 0x80, 0x18]).is_err());
    }

    // --- TpmQuote serialization tests ---

    #[test]
    fn test_tpm_quote_serialization_roundtrip() {
        let quote = TpmQuote {
            signature: "aabbccdd".to_string(),
            message: "11223344".to_string(),
            pcrs: (0..24).map(|i| format!("{:02x}", i).repeat(32)).collect(),
        };

        let json = serde_json::to_string(&quote).unwrap();
        let deserialized: TpmQuote = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.signature, quote.signature);
        assert_eq!(deserialized.message, quote.message);
        assert_eq!(deserialized.pcrs.len(), quote.pcrs.len());
    }

    // --- HCL report parsing tests ---

    /// Build a minimal HCL report for testing.
    fn build_hcl_report(tee_report: &[u8], report_type: u32, content: &[u8]) -> Vec<u8> {
        let tee_end = 0x20 + 1184;
        let content_start = tee_end + 20;
        let mut hcl = vec![0u8; content_start + content.len()];

        hcl[0..4].copy_from_slice(b"HCLA");
        let copy_len = tee_report.len().min(1184);
        hcl[0x20..0x20 + copy_len].copy_from_slice(&tee_report[..copy_len]);

        let total = (20 + content.len()) as u32;
        hcl[tee_end..tee_end + 4].copy_from_slice(&total.to_le_bytes());
        hcl[tee_end + 4..tee_end + 8].copy_from_slice(&1u32.to_le_bytes());
        hcl[tee_end + 8..tee_end + 12].copy_from_slice(&report_type.to_le_bytes());
        hcl[tee_end + 12..tee_end + 16].copy_from_slice(&1u32.to_le_bytes());
        hcl[tee_end + 16..tee_end + 20].copy_from_slice(&(content.len() as u32).to_le_bytes());
        hcl[content_start..].copy_from_slice(content);
        hcl
    }

    #[test]
    fn test_parse_hcl_report_valid_snp() {
        let content = br#"{"keys":[]}"#;
        let hcl = build_hcl_report(&[0u8; 1184], HCL_REPORT_TYPE_SNP, content);

        let parsed = parse_hcl_report(&hcl).unwrap();
        assert_eq!(parsed.tee_report.len(), 1184);
        assert_eq!(parsed.report_type, HCL_REPORT_TYPE_SNP);
        assert_eq!(parsed.var_data, content);
    }

    #[test]
    fn test_parse_hcl_report_valid_tdx() {
        let content = br#"{"keys":[]}"#;
        let hcl = build_hcl_report(&[0u8; 1184], HCL_REPORT_TYPE_TDX, content);

        let parsed = parse_hcl_report(&hcl).unwrap();
        assert_eq!(parsed.report_type, HCL_REPORT_TYPE_TDX);
        assert_eq!(parsed.var_data, content);
    }

    #[test]
    fn test_parse_hcl_report_trims_nulls() {
        let content = b"test data";
        let mut hcl = build_hcl_report(&[0u8; 1184], HCL_REPORT_TYPE_SNP, content);
        // Extend with null padding
        hcl.extend_from_slice(&[0u8; 100]);

        let parsed = parse_hcl_report(&hcl).unwrap();
        assert_eq!(parsed.var_data, content);
    }

    #[test]
    fn test_parse_hcl_report_too_short() {
        let hcl = vec![0u8; 100];
        assert!(parse_hcl_report(&hcl).is_err());
    }

    #[test]
    fn test_parse_hcl_report_bad_magic() {
        let mut hcl = build_hcl_report(&[0u8; 1184], HCL_REPORT_TYPE_SNP, b"{}");
        hcl[0..4].copy_from_slice(b"BAAD");
        assert!(parse_hcl_report(&hcl).is_err());
    }

    // --- JWK JSON extraction tests ---

    #[test]
    fn test_extract_ak_pub_from_jwk_json_valid() {
        // 256 zero bytes = 342 base64url chars (all 'A')
        let n_b64 = "A".repeat(342);
        let json_str = format!(
            r#"{{"keys":[{{"kid":"HCLAkPub","key_ops":["sign"],"kty":"RSA","e":"AQAB","n":"{}"}}]}}"#,
            n_b64
        );

        let (modulus, exponent) = extract_ak_pub_from_jwk_json(json_str.as_bytes()).unwrap();
        assert_eq!(exponent, vec![0x01, 0x00, 0x01]); // 65537
        assert_eq!(modulus.len(), 256); // RSA 2048
    }

    #[test]
    fn test_extract_ak_pub_from_jwk_json_no_ak_key() {
        let json = br#"{"keys":[{"kid":"HCLEkPub","kty":"RSA","e":"AQAB","n":"AA"}]}"#;
        assert!(extract_ak_pub_from_jwk_json(json).is_err());
    }

    #[test]
    fn test_extract_ak_pub_from_jwk_json_not_json() {
        assert!(extract_ak_pub_from_jwk_json(b"not json at all").is_err());
    }

    #[test]
    fn test_extract_ak_pub_from_jwk_json_no_keys_array() {
        let json = br#"{"data": "test"}"#;
        assert!(extract_ak_pub_from_jwk_json(json).is_err());
    }

    #[test]
    fn test_verify_tpm_signature_tries_jwk_then_tpm2b() {
        // verify_tpm_signature should accept both JWK JSON and TPM2B_PUBLIC
        // formats for var_data. This test verifies the TPM2B_PUBLIC fallback
        // still works even though JWK JSON is tried first.
        let modulus = vec![0xAB; 256];
        let var_data = build_tpm2b_public_rsa(&modulus);

        // This will fail at signature verification (dummy data) but should
        // successfully extract the key from TPM2B_PUBLIC format
        let dummy_sig = vec![0u8; 256];
        let dummy_msg = vec![0xFF, 0x54, 0x43, 0x47, 0x80, 0x18, 0x00, 0x00, 0x00, 0x00];

        let result = verify_tpm_signature(&dummy_sig, &dummy_msg, &var_data);
        // Should fail at verification step, not at key extraction
        assert!(result.is_err());
        let err = format!("{:?}", result.err().unwrap());
        assert!(
            err.contains("RSA") || err.contains("sig") || err.contains("Signature"),
            "error should be about signature verification, not key extraction: {}",
            err
        );
    }
}
