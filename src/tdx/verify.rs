use crate::tdx::pcs_client::PcsClient;
use crate::tdx::utils::{extract_sgx_extensions_from_quote, parse_sgx_key_values};
use dcap_rs::types::VerifiedOutput;
use dcap_rs::types::collaterals::IntelCollateral;
use dcap_rs::types::quotes::version_4::QuoteV4;
use dcap_rs::utils::quotes::version_4::verify_quote_dcapv4;
use flate2::read::GzDecoder;
use std::error::Error;
use std::fmt::Display;
use std::fs;
use std::io::Read;

#[derive(Debug)]
pub enum VerificationError {
    ParseError(String),
    DecompressionError(String),
    NetworkError(String),
    VerificationFailed(String),
    InvalidInput(String),
}

impl Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            VerificationError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            VerificationError::DecompressionError(msg) => write!(f, "Decompression error: {}", msg),
            VerificationError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            VerificationError::VerificationFailed(msg) => write!(f, "Verification failed: {}", msg),
            VerificationError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
        }
    }
}

impl Error for VerificationError {}

/// Verify attestation from HTTP header string
pub async fn verify_attestation(
    attestation_header: &str,
) -> Result<VerifiedOutput, VerificationError> {
    // Parse and decode the attestation
    let quote = parse_attestation_header(attestation_header)?;

    // Perform verification
    verify_quote(quote).await
}

/// Parse attestation from header string (assumes base64 + gzip format)
fn parse_attestation_header(attestation_header: &str) -> Result<QuoteV4, VerificationError> {
    let trimmed = attestation_header.trim();

    // Decode base64
    let compressed_bytes = base64::decode(trimmed)
        .map_err(|e| VerificationError::ParseError(format!("Base64 decode failed: {}", e)))?;

    // Decompress gzip
    let mut decoder = GzDecoder::new(&compressed_bytes[..]);
    let mut quote_bytes = Vec::new();
    decoder.read_to_end(&mut quote_bytes).map_err(|e| {
        VerificationError::DecompressionError(format!("Gzip decompression failed: {}", e))
    })?;

    // Parse quote
    let quote = QuoteV4::from_bytes(&quote_bytes);
    Ok(quote)
}

/// Verify a parsed quote
async fn verify_quote(quote: QuoteV4) -> Result<VerifiedOutput, VerificationError> {
    // Extract SGX extensions
    let sgx_extensions = extract_sgx_extensions_from_quote(&quote).unwrap();
    let sgx_extension_key_values = parse_sgx_key_values(&sgx_extensions);

    // Fetch collaterals
    let collaterals = fetch_collaterals(&sgx_extension_key_values.fmspc).await?;

    let current_time = chrono::Utc::now().timestamp() as u64;

    let verified_output = verify_quote_dcapv4(&quote, &collaterals, current_time);

    Ok(verified_output)
}

/// Fetch required collaterals from Intel PCS (including root certificates via HTTP)
pub async fn fetch_collaterals(fmspc: &str) -> Result<IntelCollateral, VerificationError> {
    let pcs_client = PcsClient::new();

    // Fetch all required data concurrently for better performance
    let tcb_response = pcs_client
        .get_tcb_info(fmspc)
        .await
        .map_err(|e| VerificationError::NetworkError(format!("TCB info fetch failed: {}", e)))?;

    let qe_identity = pcs_client
        .get_qe_identity()
        .await
        .map_err(|e| VerificationError::NetworkError(format!("QE identity fetch failed: {}", e)))?;

    let pck_crl = pcs_client
        .get_pck_crl("platform", "der")
        .await
        .map_err(|e| VerificationError::NetworkError(format!("PCK CRL fetch failed: {}", e)))?;

    // Fetch Intel root certificates via HTTP
    let intel_root_ca = pcs_client.get_intel_root_ca().await.map_err(|e| {
        VerificationError::NetworkError(format!("Intel Root CA fetch failed: {}", e))
    })?;

    let intel_root_ca_crl = pcs_client.get_intel_root_ca_crl().await.map_err(|e| {
        VerificationError::NetworkError(format!("Intel Root CA CRL fetch failed: {}", e))
    })?;

    let mut collaterals = IntelCollateral::new();

    // Set collateral data
    let tcb_info_bytes = tcb_response.json_to_bytes().map_err(|e| {
        VerificationError::ParseError(format!("TCB info serialization failed: {:?}", e))
    })?;
    let qe_identity_bytes = serde_json::to_vec(&qe_identity).map_err(|e| {
        VerificationError::ParseError(format!("QE identity serialization failed: {}", e))
    })?;
    let signing_cert_bytes = tcb_response.certs_to_bytes()[0].clone();

    collaterals.set_tcbinfo_bytes(&tcb_info_bytes);
    collaterals.set_qeidentity_bytes(&qe_identity_bytes);
    collaterals.set_sgx_platform_crl_der(&pck_crl);
    collaterals.set_sgx_tcb_signing_pem(&signing_cert_bytes);

    // Load root CA certificates if available
    // if let Ok(root_ca_bytes) = fs::read("data/Intel_SGX_Provisioning_Certification_RootCA2.cer") {
    //     collaterals.set_intel_root_ca_der(&root_ca_bytes);
    // }
    // if let Ok(root_ca_crl_bytes) = fs::read("data/IntelSGXRootCA.der") {
    //     collaterals.set_sgx_intel_root_ca_crl_der(&root_ca_crl_bytes);
    // }

    // Set root certificates fetched via HTTP
    collaterals.set_intel_root_ca_der(&intel_root_ca);
    collaterals.set_sgx_intel_root_ca_crl_der(&intel_root_ca_crl);

    Ok(collaterals)
}

/// Verify multiple attestations (useful for batch processing)
pub async fn verify_multiple_attestations(
    attestations: &[&str],
) -> Vec<Result<VerifiedOutput, VerificationError>> {
    let mut results = Vec::new();

    for attestation in attestations {
        let result = verify_attestation(attestation).await;
        results.push(result);
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_invalid_base64() {
        let result = verify_attestation("invalid_base64!").await;
        assert!(matches!(result, Err(VerificationError::ParseError(_))));
    }

    #[tokio::test]
    async fn test_empty_attestation() {
        let result = verify_attestation("").await;
        assert!(matches!(result, Err(VerificationError::ParseError(_))));
    }

    #[tokio::test]
    async fn test_fetch_collaterals() {
        let result = fetch_collaterals("00806F050000").await;
        assert!(
            result.is_ok(),
            "Should be able to fetch collaterals via HTTP"
        );
    }
}
