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

pub mod collateral;
pub mod error;
pub mod platforms;
pub mod types;
pub mod utils;

pub use collateral::{
    snp_crl_url, CertProvider, DefaultCertProvider, DefaultTdxCollateralProvider, HttpTimeouts,
    TdxCollateralProvider, AMD_KDS_VCEK_BASE, AMD_KDS_VLEK_BASE, INTEL_CERTS_BASE,
    INTEL_PCS_V4_BASE, INTEL_QE_IDENTITY_URL, INTEL_ROOT_CA_CRL_URL,
};
pub use error::{AttestationError, Result};
#[cfg(feature = "tdx")]
pub use platforms::tdx::dcap::{
    check_cert_revocation, check_intermediate_ca_revocation, determine_ca_type,
};
pub use types::*;

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

    // Check dstack before bare-metal TDX — on Phala CVM both may exist
    // but dstack is the correct interface for quote generation.
    #[cfg(feature = "dstack")]
    if platforms::dstack::attest::is_available() {
        return Ok(PlatformType::Dstack);
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
        #[cfg(feature = "dstack")]
        PlatformType::Dstack => {
            let evidence = platforms::dstack::attest::generate_evidence(report_data).await?;
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

    serde_json::to_vec(&envelope).map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))
}

/// Maximum accepted evidence size (10 MiB).
pub const MAX_EVIDENCE_SIZE: usize = 10 * 1024 * 1024;

/// Reusable verifier with pluggable cert/collateral providers.
///
/// Construct once (e.g. at service startup), store, and call `.verify()`
/// for each request. Uses default providers for any platform not explicitly
/// overridden.
///
/// ```rust,ignore
/// let verifier = Verifier::new()
///     .with_cert_provider(my_cached_provider);
/// let result = verifier.verify(&evidence_json, &VerifyParams::default()).await?;
/// ```
pub struct Verifier {
    cert_provider: Box<dyn CertProvider>,
    tdx_provider: Box<dyn TdxCollateralProvider>,
}

impl Verifier {
    pub fn new() -> Self {
        Self {
            cert_provider: Box::new(DefaultCertProvider::new()),
            tdx_provider: Box::new(DefaultTdxCollateralProvider::new()),
        }
    }

    pub fn with_cert_provider(mut self, provider: impl CertProvider + 'static) -> Self {
        self.cert_provider = Box::new(provider);
        self
    }

    pub fn with_tdx_provider(mut self, provider: impl TdxCollateralProvider + 'static) -> Self {
        self.tdx_provider = Box::new(provider);
        self
    }

    /// Verify attestation evidence from a self-describing JSON envelope.
    ///
    /// The evidence JSON must be an [`AttestationEvidence`] envelope containing
    /// a `platform` field and an `evidence` payload. The platform is auto-detected
    /// from the envelope and the correct verifier is dispatched automatically.
    pub async fn verify(
        &self,
        evidence_json: &[u8],
        params: &VerifyParams,
    ) -> Result<VerificationResult> {
        // Bounded deserialization — reject oversized evidence before parsing
        if evidence_json.len() > MAX_EVIDENCE_SIZE {
            return Err(AttestationError::EvidenceTooLarge {
                size: evidence_json.len(),
                max: MAX_EVIDENCE_SIZE,
            });
        }

        // Validate expected_report_data size (all platforms use at most 64 bytes)
        if let Some(ref data) = params.expected_report_data {
            if data.len() > 64 {
                return Err(AttestationError::ReportDataTooLarge { max: 64 });
            }
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
                platforms::snp::verify::verify_evidence(
                    &evidence,
                    params,
                    self.cert_provider.as_ref(),
                )
                .await
            }
            #[cfg(feature = "tdx")]
            PlatformType::Tdx => {
                let evidence: platforms::tdx::evidence::TdxEvidence =
                    serde_json::from_value(envelope.evidence)
                        .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?;
                platforms::tdx::verify::verify_evidence(
                    &evidence,
                    params,
                    Some(self.tdx_provider.as_ref()),
                )
                .await
            }
            #[cfg(feature = "az-snp")]
            PlatformType::AzSnp => {
                let evidence: platforms::az_snp::evidence::AzSnpEvidence =
                    serde_json::from_value(envelope.evidence)
                        .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?;
                platforms::az_snp::verify::verify_evidence(
                    &evidence,
                    params,
                    self.cert_provider.as_ref(),
                )
                .await
            }
            #[cfg(feature = "az-tdx")]
            PlatformType::AzTdx => {
                let evidence: platforms::az_tdx::evidence::AzTdxEvidence =
                    serde_json::from_value(envelope.evidence)
                        .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?;
                platforms::az_tdx::verify::verify_evidence(
                    &evidence,
                    params,
                    Some(self.tdx_provider.as_ref()),
                )
                .await
            }
            #[cfg(feature = "dstack")]
            PlatformType::Dstack => {
                let evidence: platforms::dstack::evidence::DstackEvidence =
                    serde_json::from_value(envelope.evidence)
                        .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?;
                platforms::dstack::verify::verify_evidence(
                    &evidence,
                    params,
                    Some(self.tdx_provider.as_ref()),
                )
                .await
            }
            _other => {
                let _ = params;
                Err(AttestationError::PlatformNotEnabled(_other.to_string()))
            }
        }
    }
}

impl Default for Verifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Verify attestation evidence from a self-describing JSON envelope.
///
/// Convenience wrapper around [`Verifier`] with default providers.
/// For custom providers (e.g. cached certs), construct a [`Verifier`] instead.
pub async fn verify(evidence_json: &[u8], params: &VerifyParams) -> Result<VerificationResult> {
    Verifier::new().verify(evidence_json, params).await
}
