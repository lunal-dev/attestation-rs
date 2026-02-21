use wasm_bindgen::prelude::*;

use attestation::platforms::snp::certs::get_bundled_certs;
use attestation::platforms::snp::claims::extract_claims;
use attestation::platforms::snp::verify::{
    parse_report, verify_cert_chain_pub, verify_report_signature,
};
use attestation::types::ProcessorGeneration;
use attestation::utils::{constant_time_eq, pad_report_data};

/// Verify live SNP evidence in WASM.
///
/// - `evidence_json`: evidence JSON with inline cert_chain.vcek
/// - `generation`: processor generation ("milan", "genoa", "turin")
/// - `expected_report_data`: optional raw bytes to check against report_data in the report
///
/// Returns verification result as JSON.
#[wasm_bindgen]
pub fn verify_snp(
    evidence_json: &str,
    generation: &str,
    expected_report_data: Option<Vec<u8>>,
) -> Result<String, JsError> {
    let gen = match generation {
        "milan" | "Milan" => ProcessorGeneration::Milan,
        "genoa" | "Genoa" => ProcessorGeneration::Genoa,
        "turin" | "Turin" => ProcessorGeneration::Turin,
        _ => return Err(JsError::new(&format!("unknown generation: {}", generation))),
    };

    let evidence: attestation::platforms::snp::evidence::SnpEvidence =
        serde_json::from_str(evidence_json)
            .map_err(|e| JsError::new(&format!("evidence deserialize: {}", e)))?;

    use base64::Engine;
    let report_bytes = base64::engine::general_purpose::STANDARD
        .decode(&evidence.attestation_report)
        .map_err(|e| JsError::new(&format!("base64 decode report: {}", e)))?;

    let report = parse_report(&report_bytes)
        .map_err(|e| JsError::new(&format!("parse report: {}", e)))?;

    // Get VCEK from evidence
    let vcek_der = match &evidence.cert_chain {
        Some(chain) => base64::engine::general_purpose::STANDARD
            .decode(&chain.vcek)
            .map_err(|e| JsError::new(&format!("base64 decode vcek: {}", e)))?,
        None => return Err(JsError::new("evidence missing cert_chain.vcek")),
    };

    // Verify cert chain (bundled ARK/ASK -> VCEK)
    let (ark, ask) = get_bundled_certs(gen);
    verify_cert_chain_pub(ark, ask, &vcek_der)
        .map_err(|e| JsError::new(&format!("cert chain verify: {}", e)))?;

    // Verify report signature
    verify_report_signature(&report_bytes, &vcek_der)
        .map_err(|e| JsError::new(&format!("report signature: {}", e)))?;

    // Check report_data binding
    let report_data_match = expected_report_data.map(|expected| {
        let padded = pad_report_data(&expected, 64).unwrap_or_default();
        constant_time_eq(&report.report_data[..], &padded)
    });

    // Extract claims
    let claims = extract_claims(&report);

    let result = serde_json::json!({
        "signature_valid": true,
        "platform": "snp",
        "report_version": report.version,
        "report_data_match": report_data_match,
        "claims": claims,
    });

    serde_json::to_string_pretty(&result)
        .map_err(|e| JsError::new(&format!("json serialize: {}", e)))
}
