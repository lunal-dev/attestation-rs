use axum::extract::State;
use axum::Json;
#[cfg(target_os = "linux")]
use base64::engine::general_purpose::STANDARD as BASE64;
#[cfg(target_os = "linux")]
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::ApiError;
use crate::AppState;

#[derive(Deserialize)]
pub struct AttestRequest {
    pub report_data: Option<String>,
    #[serde(default = "default_platform")]
    pub platform: String,
}

fn default_platform() -> String {
    "auto".to_string()
}

#[derive(Serialize)]
pub struct AttestResponse {
    pub platform: String,
    pub evidence: Value,
}

pub async fn handler(
    State(state): State<AppState>,
    Json(req): Json<AttestRequest>,
) -> Result<Json<AttestResponse>, ApiError> {
    if !state.config.attestation.enabled {
        return Err(ApiError::AttestNotAvailable);
    }

    #[cfg(target_os = "linux")]
    {
        let report_data = match req.report_data {
            Some(b64) => BASE64
                .decode(&b64)
                .map_err(|e| ApiError::BadRequest(format!("invalid base64 report_data: {e}")))?,
            None => Vec::new(),
        };

        let platform = resolve_platform(&req.platform)?;
        let evidence_bytes = attestation::attest(
            platform,
            &report_data,
            &attestation::AttestOptions::default(),
        )
        .await?;
        let envelope: Value = serde_json::from_slice(&evidence_bytes)
            .map_err(|e| ApiError::Internal(format!("failed to parse evidence: {e}")))?;

        // attestation::attest returns an AttestationEvidence envelope
        // (`{platform, evidence}`); /attest's contract is to return the
        // platform-specific evidence directly so callers can wrap it
        // in their own envelope before sending to /verify.
        Ok(Json(AttestResponse {
            platform: format!("{platform}"),
            evidence: envelope.get("evidence").cloned().unwrap_or(envelope),
        }))
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = req;
        Err(ApiError::NoPlatform)
    }
}

#[cfg(target_os = "linux")]
fn resolve_platform(name: &str) -> Result<attestation::PlatformType, ApiError> {
    match name {
        "auto" => attestation::detect().map_err(|_| ApiError::NoPlatform),
        "snp" => Ok(attestation::PlatformType::Snp),
        "tdx" => Ok(attestation::PlatformType::Tdx),
        "az-snp" => Ok(attestation::PlatformType::AzSnp),
        "az-tdx" => Ok(attestation::PlatformType::AzTdx),
        "gcp-snp" => Ok(attestation::PlatformType::GcpSnp),
        "gcp-tdx" => Ok(attestation::PlatformType::GcpTdx),
        other => Err(ApiError::BadRequest(format!("unknown platform: {other}"))),
    }
}
