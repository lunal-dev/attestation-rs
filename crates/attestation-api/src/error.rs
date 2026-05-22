use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("verification failed: {0}")]
    Verification(#[from] attestation::AttestationError),

    #[error("no TEE platform detected")]
    NoPlatform,

    #[error("attestation is disabled")]
    AttestNotAvailable,

    #[error("invalid request: {0}")]
    BadRequest(String),

    #[error("cert fetch failed: {0}")]
    CertFetch(String),

    #[error("token issuer not configured")]
    TokenNotConfigured,

    #[error("internal error: {0}")]
    Internal(String),
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error_key) = match &self {
            ApiError::Verification(_) => (StatusCode::UNPROCESSABLE_ENTITY, "verification_failed"),
            ApiError::NoPlatform => (StatusCode::SERVICE_UNAVAILABLE, "no_platform"),
            ApiError::AttestNotAvailable => (StatusCode::BAD_REQUEST, "attest_not_available"),
            ApiError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            ApiError::CertFetch(_) => (StatusCode::BAD_GATEWAY, "cert_fetch_failed"),
            ApiError::TokenNotConfigured => (StatusCode::BAD_REQUEST, "token_not_configured"),
            ApiError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };

        let message = match &self {
            ApiError::Internal(detail) => {
                tracing::error!(detail, "internal error");
                "an internal error occurred".to_string()
            }
            other => other.to_string(),
        };

        let body = ErrorBody {
            error: error_key,
            message,
        };

        (status, axum::Json(body)).into_response()
    }
}
