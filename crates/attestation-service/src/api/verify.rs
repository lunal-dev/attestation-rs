use axum::extract::State;
use axum::Json;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::ApiError;
use crate::AppState;

#[derive(Deserialize)]
pub struct VerifyRequest {
    pub evidence: Value,
    #[serde(default)]
    pub params: VerifyParamsInput,
    #[serde(default)]
    pub issue_token: bool,
}

#[derive(Deserialize, Default)]
pub struct VerifyParamsInput {
    pub expected_report_data: Option<String>,
    pub expected_init_data_hash: Option<String>,
    #[serde(default)]
    pub allow_debug: bool,
    pub min_tcb: Option<MinTcbInput>,
}

#[derive(Deserialize)]
pub struct MinTcbInput {
    pub bootloader: u8,
    pub tee: u8,
    pub snp: u8,
    pub microcode: u8,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    pub result: attestation::VerificationResult,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

pub async fn handler(
    State(state): State<AppState>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, ApiError> {
    let evidence_json = serde_json::to_vec(&req.evidence)
        .map_err(|e| ApiError::BadRequest(format!("invalid evidence JSON: {e}")))?;

    let expected_report_data = req
        .params
        .expected_report_data
        .map(|s| BASE64.decode(&s))
        .transpose()
        .map_err(|e| ApiError::BadRequest(format!("invalid base64 report_data: {e}")))?;

    let expected_init_data_hash = req
        .params
        .expected_init_data_hash
        .map(|s| BASE64.decode(&s))
        .transpose()
        .map_err(|e| ApiError::BadRequest(format!("invalid base64 init_data_hash: {e}")))?;

    let min_tcb = req.params.min_tcb.map(|t| attestation::SnpTcb {
        bootloader: t.bootloader,
        tee: t.tee,
        snp: t.snp,
        microcode: t.microcode,
        fmc: None,
    });

    let allow_debug = req.params.allow_debug;
    if allow_debug && !state.config.attestation.allow_debug {
        return Err(ApiError::BadRequest(
            "allow_debug is disabled by server configuration".to_string(),
        ));
    }

    let params = attestation::VerifyParams {
        expected_report_data,
        expected_init_data_hash,
        allow_debug,
        min_tcb,
    };

    let result = state.verifier.verify(&evidence_json, &params).await?;

    let token = if req.issue_token {
        let issuer = state
            .token_issuer
            .as_ref()
            .ok_or(ApiError::TokenNotConfigured)?;
        Some(issuer.issue(&result)?)
    } else {
        None
    };

    Ok(Json(VerifyResponse { result, token }))
}
