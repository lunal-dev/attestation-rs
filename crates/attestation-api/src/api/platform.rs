use axum::Json;
use serde::Serialize;

use crate::error::ApiError;

#[derive(Serialize)]
pub struct PlatformResponse {
    pub platform: String,
}

pub async fn handler() -> Result<Json<PlatformResponse>, ApiError> {
    #[cfg(target_os = "linux")]
    {
        let platform = attestation::detect().map_err(|_| ApiError::NoPlatform)?;
        Ok(Json(PlatformResponse {
            platform: format!("{platform}"),
        }))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(ApiError::NoPlatform)
    }
}
