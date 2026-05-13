use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::AppState;

/// Constant-time comparison of an API key against all configured keys.
/// Keys are hashed with SHA-256 before comparison to prevent timing
/// side-channels that could leak key lengths.
fn verify_api_key(provided: &str, keys: &[String]) -> bool {
    let provided_hash: [u8; 32] = Sha256::digest(provided.as_bytes()).into();
    let mut found = subtle::Choice::from(0);
    for expected in keys {
        let expected_hash: [u8; 32] = Sha256::digest(expected.as_bytes()).into();
        found |= expected_hash.ct_eq(&provided_hash);
    }
    bool::from(found)
}

pub async fn api_key_auth(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let header_value = match request.headers().get("authorization") {
        Some(v) => v,
        None => {
            tracing::warn!("rejected request without Authorization header");
            return error_response(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "missing Authorization header",
            );
        }
    };

    let header_str = match header_value.to_str() {
        Ok(s) => s,
        Err(_) => {
            tracing::warn!("rejected request with non-ASCII Authorization header");
            return error_response(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "malformed Authorization header",
            );
        }
    };

    match header_str.strip_prefix("Bearer ") {
        Some(key) if verify_api_key(key, &state.config.auth.api_keys) => next.run(request).await,
        Some(_) => {
            tracing::warn!("rejected request with invalid API key");
            error_response(StatusCode::UNAUTHORIZED, "unauthorized", "invalid API key")
        }
        None => {
            tracing::warn!("rejected request with unsupported Authorization scheme");
            error_response(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "Authorization header must use Bearer scheme",
            )
        }
    }
}

fn error_response(status: StatusCode, error: &str, message: &str) -> Response {
    (
        status,
        Json(json!({
            "error": error,
            "message": message,
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_prefix_of_valid_key() {
        let keys = vec!["secret_extended".to_string()];
        assert!(!verify_api_key("secret", &keys));
    }

    #[test]
    fn rejects_longer_key_containing_valid() {
        let keys = vec!["abc".to_string()];
        assert!(!verify_api_key("abcdef", &keys));
    }

    #[test]
    fn accepts_exact_match() {
        let keys = vec!["my-secret-key".to_string()];
        assert!(verify_api_key("my-secret-key", &keys));
    }

    #[test]
    fn rejects_empty_provided_key() {
        let keys = vec!["nonempty".to_string()];
        assert!(!verify_api_key("", &keys));
    }

    #[test]
    fn rejects_when_no_keys_configured() {
        let keys: Vec<String> = vec![];
        assert!(!verify_api_key("anything", &keys));
    }

    #[test]
    fn accepts_second_key_in_list() {
        let keys = vec!["first-key".to_string(), "second-key".to_string()];
        assert!(verify_api_key("second-key", &keys));
        assert!(verify_api_key("first-key", &keys));
        assert!(!verify_api_key("third-key", &keys));
    }
}
