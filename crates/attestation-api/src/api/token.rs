use axum::extract::State;
use axum::Json;
use serde_json::Value;

use crate::error::ApiError;
use crate::AppState;

/// Returns the JWKS (JSON Web Key Set) containing the public key used
/// to sign attestation JWTs. Relying parties use this to verify tokens.
pub async fn jwks(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let issuer = state
        .token_issuer
        .as_ref()
        .ok_or(ApiError::TokenNotConfigured)?;
    Ok(Json(issuer.jwks()))
}
