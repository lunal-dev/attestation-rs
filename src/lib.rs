//! Unified TEE attestation evidence generation and verification.
//!
//! This library provides a single interface for generating and verifying
//! attestation evidence across multiple Trusted Execution Environment (TEE)
//! platforms: AMD SEV-SNP, Intel TDX, Azure SEV-SNP (vTPM), and Azure TDX (vTPM).
//!
//! # Platform Support
//!
//! Each platform can be individually enabled via cargo features:
//! `snp`, `tdx`, `az-snp`, `az-tdx` (all on by default).
//! Evidence generation requires the `attest` feature and Linux with TEE hardware.
//!
//! # Quick Start
//!
//! **Verifier** (any machine, including WASM):
//! ```rust,ignore
//! use attestation::types::VerifyParams;
//!
//! let result = attestation::verify(&evidence_json, &VerifyParams::default()).await?;
//! assert!(result.signature_valid);
//! ```
//!
//! **Attester** (inside TEE, with `attest` feature):
//! ```rust,ignore
//! let platform = attestation::detect()?;
//! let evidence_json = attestation::attest(platform, b"nonce").await?;
//! ```

pub mod error;
pub mod types;
pub mod platforms;
pub mod collateral;
pub mod utils;

pub use error::{AttestationError, Result};
pub use types::*;
pub use collateral::{CertProvider, DefaultCertProvider};

/// Detect the current TEE platform.
/// Checks Azure variants first (they also have bare-metal device paths),
/// then bare-metal variants.
#[cfg(all(feature = "attest", target_os = "linux"))]
pub fn detect() -> Result<PlatformType> {
    #[cfg(feature = "az-tdx")]
    if platforms::az_tdx::attest::is_available() {
        return Ok(PlatformType::AzTdx);
    }

    #[cfg(feature = "az-snp")]
    if platforms::az_snp::attest::is_available() {
        return Ok(PlatformType::AzSnp);
    }

    #[cfg(feature = "tdx")]
    if platforms::tdx::attest::is_available() {
        return Ok(PlatformType::Tdx);
    }

    #[cfg(feature = "snp")]
    if platforms::snp::attest::is_available() {
        return Ok(PlatformType::Snp);
    }

    Err(AttestationError::NoPlatformDetected)
}

/// Generate attestation evidence and wrap it in a self-describing envelope.
///
/// Returns JSON bytes containing an [`AttestationEvidence`] envelope with
/// the platform tag and platform-specific evidence payload.
#[cfg(all(feature = "attest", target_os = "linux"))]
pub async fn attest(platform: PlatformType, report_data: &[u8]) -> Result<Vec<u8>> {
    #[allow(unreachable_patterns)]
    let evidence_value = match platform {
        #[cfg(feature = "snp")]
        PlatformType::Snp => {
            let evidence = platforms::snp::attest::generate_evidence(report_data).await?;
            serde_json::to_value(&evidence)
                .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?
        }
        #[cfg(feature = "tdx")]
        PlatformType::Tdx => {
            let evidence = platforms::tdx::attest::generate_evidence(report_data).await?;
            serde_json::to_value(&evidence)
                .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?
        }
        #[cfg(feature = "az-snp")]
        PlatformType::AzSnp => {
            let evidence = platforms::az_snp::attest::generate_evidence(report_data).await?;
            serde_json::to_value(&evidence)
                .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?
        }
        #[cfg(feature = "az-tdx")]
        PlatformType::AzTdx => {
            let evidence = platforms::az_tdx::attest::generate_evidence(report_data).await?;
            serde_json::to_value(&evidence)
                .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?
        }
        _other => {
            let _ = report_data;
            return Err(AttestationError::PlatformNotEnabled(_other.to_string()));
        }
    };

    let envelope = AttestationEvidence {
        platform,
        evidence: evidence_value,
    };

    serde_json::to_vec(&envelope)
        .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))
}

/// Maximum accepted evidence size (10 MiB).
pub const MAX_EVIDENCE_SIZE: usize = 10 * 1024 * 1024;

/// Verify attestation evidence from a self-describing JSON envelope.
///
/// The evidence JSON must be an [`AttestationEvidence`] envelope containing
/// a `platform` field and an `evidence` payload. The platform is auto-detected
/// from the envelope and the correct verifier is dispatched automatically.
pub async fn verify(evidence_json: &[u8], params: &VerifyParams) -> Result<VerificationResult> {
    // M8: Bounded deserialization — reject oversized evidence before parsing
    if evidence_json.len() > MAX_EVIDENCE_SIZE {
        return Err(AttestationError::EvidenceTooLarge {
            size: evidence_json.len(),
            max: MAX_EVIDENCE_SIZE,
        });
    }

    let envelope: AttestationEvidence = serde_json::from_slice(evidence_json)
        .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?;

    #[allow(unreachable_patterns)]
    match envelope.platform {
        #[cfg(feature = "snp")]
        PlatformType::Snp => {
            let evidence: platforms::snp::evidence::SnpEvidence =
                serde_json::from_value(envelope.evidence)
                    .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?;
            let provider = DefaultCertProvider::new();
            platforms::snp::verify::verify_evidence(&evidence, params, &provider).await
        }
        #[cfg(feature = "tdx")]
        PlatformType::Tdx => {
            let evidence: platforms::tdx::evidence::TdxEvidence =
                serde_json::from_value(envelope.evidence)
                    .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?;
            platforms::tdx::verify::verify_evidence(&evidence, params).await
        }
        #[cfg(feature = "az-snp")]
        PlatformType::AzSnp => {
            let evidence: platforms::az_snp::evidence::AzSnpEvidence =
                serde_json::from_value(envelope.evidence)
                    .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?;
            let provider = DefaultCertProvider::new();
            platforms::az_snp::verify::verify_evidence(&evidence, params, &provider).await
        }
        #[cfg(feature = "az-tdx")]
        PlatformType::AzTdx => {
            let evidence: platforms::az_tdx::evidence::AzTdxEvidence =
                serde_json::from_value(envelope.evidence)
                    .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?;
            platforms::az_tdx::verify::verify_evidence(&evidence, params).await
        }
        _other => {
            let _ = params;
            Err(AttestationError::PlatformNotEnabled(_other.to_string()))
        }
    }
}
