use attestation::types::VerifyParams;
use wasm_bindgen::prelude::*;

/// Verify a self-describing attestation evidence envelope.
///
/// - `evidence_json`: an [`attestation::AttestationEvidence`] envelope (JSON).
/// - `expected_report_data`: optional raw bytes to check against the report's
///   `report_data` for nonce binding.
///
/// Returns the [`attestation::VerificationResult`] serialized as JSON.
#[wasm_bindgen]
pub async fn verify(
    evidence_json: &str,
    expected_report_data: Option<Vec<u8>>,
) -> Result<String, JsError> {
    let params = VerifyParams {
        expected_report_data,
        ..Default::default()
    };
    let result = attestation::verify(evidence_json.as_bytes(), &params)
        .await
        .map_err(|e| JsError::new(&format!("verify failed: {e}")))?;
    serde_json::to_string(&result).map_err(|e| JsError::new(&format!("serialize: {e}")))
}
