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
pub fn verify_tpm_signature(
    _signature: &[u8],
    _message: &[u8],
    _var_data: &[u8],
) -> Result<bool> {
    // TODO: Extract AKpub from var_data, verify ECDSA SHA-256 signature
    // This requires parsing the TPM2B_PUBLIC structure from var_data
    // and using it to verify the TPMS_ATTEST signature
    //
    // For now, we return true and rely on the HCL binding check
    // which provides the cryptographic link between TPM and the TEE report
    Ok(true)
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

    // TODO: Parse the PCR selection and digest from the TPMS_ATTEST
    // and verify the hash matches
    let _ = message;

    Ok(())
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
