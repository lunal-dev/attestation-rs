use rsa::pkcs1v15::VerifyingKey as RsaVerifyingKey;
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use serde::{Deserialize, Serialize};

use crate::error::{AttestationError, Result};

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
/// report's variable data as a TPM2B_PUBLIC structure.
pub fn verify_tpm_signature(
    signature: &[u8],
    message: &[u8],
    var_data: &[u8],
) -> Result<bool> {
    // Extract the RSA public key from the HCL var_data
    let (modulus, exponent) = extract_ak_pub_from_var_data(var_data)?;

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
fn extract_ak_pub_from_var_data(var_data: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
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
}
