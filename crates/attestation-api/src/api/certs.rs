use axum::extract::State;
use axum::Json;
use serde::Serialize;
use serde_json::Value;

use crate::error::ApiError;
use crate::AppState;

#[derive(Serialize)]
pub struct CertStatusResponse {
    pub snp_chains_cached: Vec<String>,
    pub vcek_count: u64,
    pub tdx_collateral_count: u64,
    pub crl_status: Value,
}

pub async fn status(State(state): State<AppState>) -> Json<CertStatusResponse> {
    let cache = &state.cert_cache;
    Json(CertStatusResponse {
        snp_chains_cached: cache.cached_chain_names().await,
        vcek_count: cache.vcek_entry_count(),
        tdx_collateral_count: cache.tdx_entry_count(),
        crl_status: cache.crl_status_json().await,
    })
}

pub async fn refresh(State(state): State<AppState>) -> Result<Json<CertStatusResponse>, ApiError> {
    state
        .cert_cache
        .refresh_all()
        .await
        .map_err(|e| ApiError::CertFetch(e.to_string()))?;

    Ok(Json(CertStatusResponse {
        snp_chains_cached: state.cert_cache.cached_chain_names().await,
        vcek_count: state.cert_cache.vcek_entry_count(),
        tdx_collateral_count: state.cert_cache.tdx_entry_count(),
        crl_status: state.cert_cache.crl_status_json().await,
    }))
}
