//! NVIDIA GPU confidential-compute attestation.
//!
//! This module verifies CC-mode NVIDIA GPU evidence (Hopper, Blackwell) and
//! NVSwitch evidence (LS10) by delegating signature/measurement checks to
//! NVIDIA's Remote Attestation Service (NRAS). NRAS returns a signed EAT
//! (Entity Attestation Token, RFC 9711) which is verified locally against
//! NRAS's JWKS.
//!
//! Verification is pure JSON + JWS (ES384) + base64 + SHA-256, so it works on
//! every target the rest of this library supports — including `wasm32` — with
//! no FFI to NVIDIA's Python/C++ SDKs.
//!
//! ## Trust model
//!
//! The GPU evidence is **transitively** bound to the CPU TEE evidence: the
//! caller supplies a `user_nonce`; the attester derives the GPU SPDM nonce
//! `gpu_nonce = SHA256(user_nonce || domain_tag)`; the verifier rederives the
//! same value and checks NRAS attested to it via `eat_nonce`. Because the
//! same `user_nonce` is the basis of the CPU TEE `report_data`, a verifier
//! that accepts both quotes proves that **both** the CPU and the GPU
//! committed to the caller's nonce in the same attestation session.
//!
//! Relying on NRAS shifts trust to NVIDIA's signing key. A future
//! `gpu-local` feature will perform the same checks locally without NRAS.
//!
//! ## Endpoints
//!
//! Defaults match NVIDIA's production deployment and can be overridden via
//! [`DefaultNrasProvider::with_urls`] or environment variables
//! `NV_NRAS_GPU_URL` / `NV_NRAS_SWITCH_URL`. The relying-party usage of NRAS
//! is governed by NVIDIA's attestation T&C; see README.

pub mod binding;
pub mod claims;
pub mod provider;
pub mod verify_nras;

#[cfg(all(feature = "nvidia-gpu-attest", target_os = "linux"))]
pub mod attest;

pub use binding::{gpu_nonce, switch_nonce};
pub use provider::{
    jwks_url_for_endpoint, DefaultNrasProvider, Jwks, JwksKey, NrasProvider, NrasRequest,
};
pub use verify_nras::verify_bundle;

use crate::error::{AttestationError, Result};

/// Minimum acceptable length for the GPU user nonce.
///
/// Enforced symmetrically on both the attest and verify paths so a caller
/// can't produce evidence that their own verifier will reject.
pub(crate) const MIN_GPU_USER_NONCE_LEN: usize = 16;

/// Reject GPU user nonces shorter than [`MIN_GPU_USER_NONCE_LEN`].
///
/// Integration-tested via `verify_bundle` in `verify_nras::tests`; the attest
/// path call site is verified by code review (FFI-gated, not exercised by CI).
pub(crate) fn check_user_nonce_len(user_nonce: &[u8]) -> Result<()> {
    if user_nonce.len() < MIN_GPU_USER_NONCE_LEN {
        Err(AttestationError::NvidiaGpuNonceTooShort(user_nonce.len()))
    } else {
        Ok(())
    }
}
