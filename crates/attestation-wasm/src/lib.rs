use wasm_bindgen::prelude::*;

use attestation::platforms::snp::certs::get_bundled_certs;
use attestation::platforms::snp::claims::extract_claims;
use attestation::platforms::snp::verify::{
    parse_report, verify_cert_chain, verify_report_signature,
};
use attestation::platforms::tpm_common::{decode_tpm_quote, extract_tpm_nonce};
use attestation::types::{ProcessorGeneration, VerifyParams};
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
        _ => return Err(JsError::new(&format!("unknown generation: {generation}"))),
    };

    let evidence: attestation::platforms::snp::evidence::SnpEvidence =
        serde_json::from_str(evidence_json)
            .map_err(|e| JsError::new(&format!("evidence deserialize: {e}")))?;

    use base64::Engine;
    let report_bytes = base64::engine::general_purpose::STANDARD
        .decode(&evidence.attestation_report)
        .map_err(|e| JsError::new(&format!("base64 decode report: {e}")))?;

    let report =
        parse_report(&report_bytes).map_err(|e| JsError::new(&format!("parse report: {e}")))?;

    // Get VCEK from evidence
    let vcek_der = match &evidence.cert_chain {
        Some(chain) => base64::engine::general_purpose::STANDARD
            .decode(&chain.vcek)
            .map_err(|e| JsError::new(&format!("base64 decode vcek: {e}")))?,
        None => return Err(JsError::new("evidence missing cert_chain.vcek")),
    };

    // Verify cert chain (bundled ARK/ASK -> VCEK)
    let (ark, ask) = get_bundled_certs(gen);
    verify_cert_chain(ark, ask, &vcek_der)
        .map_err(|e| JsError::new(&format!("cert chain verify: {e}")))?;

    // Verify report signature
    verify_report_signature(&report_bytes, &vcek_der)
        .map_err(|e| JsError::new(&format!("report signature: {e}")))?;

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

    serde_json::to_string_pretty(&result).map_err(|e| JsError::new(&format!("json serialize: {e}")))
}

/// Verify Azure SEV-SNP (az-snp) vTPM attestation evidence in WASM.
///
/// Unlike [`verify_snp`], which only checks the bare SNP hardware report, this
/// verifies the full az-snp evidence: the HCL-wrapped SNP report **and** the
/// vTPM quote that binds freshness. The freshness anchor for az-snp lives in
/// the TPM quote's `extraData` (qualifyingData), not in the SNP `report_data`
/// — the SNP `report_data` instead binds the vTPM attestation key (AK).
///
/// Verification (mirrors the native async path, minus the CRL revocation check
/// which needs an async cert provider — so `collateral_verified` is always
/// `false` here):
/// 1. Verify the TPM quote signature with the AK extracted from HCL var_data.
/// 2. Check the quote's `extraData` equals `expected_report_data` (freshness).
/// 3. Verify the PCR digest, and optionally bind PCR[8] to `expected_init_data_hash`.
/// 4. Bind the AK to the TEE: `snp.report_data[..32] == SHA-256(var_data)`.
/// 5. Validate the VCEK chain (auto-detecting the generation from CPUID) and the
///    SNP report signature, then enforce VMPL/debug/TCB policy.
///
/// - `evidence_json`: az-snp evidence JSON (`{ version, tpm_quote, hcl_report, vcek }`)
/// - `expected_report_data`: optional raw bytes the TPM quote `extraData` must equal
/// - `expected_init_data_hash`: optional 32-byte hash to bind against PCR[8]
///
/// Returns the verification result as JSON, or throws on any check failure.
#[wasm_bindgen]
pub fn verify_az_snp(
    evidence_json: &str,
    expected_report_data: Option<Vec<u8>>,
    expected_init_data_hash: Option<Vec<u8>>,
) -> Result<String, JsError> {
    let evidence: attestation::platforms::az_snp::evidence::AzSnpEvidence =
        serde_json::from_str(evidence_json)
            .map_err(|e| JsError::new(&format!("evidence deserialize: {e}")))?;

    // Run the full az-snp verification core, but WITHOUT the report_data check:
    // the native core fails closed (throws) on a freshness mismatch, whereas the
    // WASM boundary mirrors `verify_snp` by reporting the match as a non-throwing
    // bool so the JS policy layer (requireFreshness) decides pass/fail uniformly
    // across platforms. Everything else (TPM signature, AK→TEE binding, PCR
    // integrity, VCEK chain, report signature, VMPL/debug/TCB) still fails closed.
    let params = VerifyParams {
        expected_report_data: None,
        expected_init_data_hash,
        ..VerifyParams::default()
    };

    let verified =
        attestation::platforms::az_snp::verify::verify_evidence_no_crl(&evidence, &params)
            .map_err(|e| JsError::new(&format!("az-snp verify: {e}")))?;

    // Freshness binding: compare the TPM quote's extraData (qualifyingData) to the
    // expected anchor. This is the az-snp equivalent of verify_snp's report_data
    // check — the anchor lives in the quote, not the SNP report_data. Length-exact
    // comparison matches the native verify_tpm_nonce contract (no zero-padding).
    let report_data_match = match expected_report_data {
        Some(expected) => {
            let (_sig, tpm_msg, _pcrs) = decode_tpm_quote(&evidence.tpm_quote)
                .map_err(|e| JsError::new(&format!("decode tpm quote: {e}")))?;
            let nonce = extract_tpm_nonce(&tpm_msg)
                .map_err(|e| JsError::new(&format!("extract tpm nonce: {e}")))?;
            Some(nonce.len() == expected.len() && constant_time_eq(&nonce, &expected))
        }
        None => None,
    };

    // Serialize the VerificationResult, then graft on report_version and the
    // freshness match, matching the shape verify_snp returns so the JS policy
    // layer reads both uniformly.
    let mut result = serde_json::to_value(&verified.result)
        .map_err(|e| JsError::new(&format!("json serialize: {e}")))?;
    result["report_data_match"] = serde_json::json!(report_data_match);
    result["report_version"] = serde_json::json!(verified.report_version);

    serde_json::to_string_pretty(&result).map_err(|e| JsError::new(&format!("json serialize: {e}")))
}
