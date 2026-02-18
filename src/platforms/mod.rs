use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};

use crate::error::Result;
use crate::types::{PlatformType, VerificationResult, VerifyParams};

/// Every platform module implements this trait.
#[async_trait]
pub trait Platform: Send + Sync {
    /// The concrete evidence type for this platform.
    type Evidence: Serialize + DeserializeOwned + Send + Sync;

    /// Return the platform type identifier.
    fn platform_type(&self) -> PlatformType;

    /// Generate attestation evidence from inside the TEE.
    /// `report_data`: caller-supplied nonce (up to 64 bytes) baked into the HW quote.
    #[cfg(feature = "attest")]
    async fn attest(&self, report_data: &[u8]) -> Result<Self::Evidence>;

    /// Verify attestation evidence.
    async fn verify(
        &self,
        evidence: &Self::Evidence,
        params: &VerifyParams,
    ) -> Result<VerificationResult>;
}

/// Type-erased platform for dynamic dispatch (used by detect()).
#[async_trait]
pub trait ErasedPlatform: Send + Sync {
    /// Generate evidence as serialized JSON bytes.
    #[cfg(feature = "attest")]
    async fn attest_json(&self, report_data: &[u8]) -> Result<Vec<u8>>;

    /// Verify evidence from serialized JSON bytes.
    async fn verify_json(
        &self,
        evidence_json: &[u8],
        params: &VerifyParams,
    ) -> Result<VerificationResult>;

    /// Return the platform type.
    fn platform_type(&self) -> PlatformType;
}

/// Blanket implementation: any concrete Platform is also an ErasedPlatform.
#[async_trait]
impl<T> ErasedPlatform for T
where
    T: Platform + Send + Sync,
    T::Evidence: 'static,
{
    #[cfg(feature = "attest")]
    async fn attest_json(&self, report_data: &[u8]) -> Result<Vec<u8>> {
        let evidence = self.attest(report_data).await?;
        serde_json::to_vec(&evidence)
            .map_err(|e| crate::error::AttestationError::EvidenceDeserialize(e.to_string()))
    }

    async fn verify_json(
        &self,
        evidence_json: &[u8],
        params: &VerifyParams,
    ) -> Result<VerificationResult> {
        let evidence: T::Evidence = serde_json::from_slice(evidence_json)
            .map_err(|e| crate::error::AttestationError::EvidenceDeserialize(e.to_string()))?;
        self.verify(&evidence, params).await
    }

    fn platform_type(&self) -> PlatformType {
        Platform::platform_type(self)
    }
}

#[cfg(feature = "tdx")]
pub mod tdx;

#[cfg(feature = "snp")]
pub mod snp;

// Shared TPM types and verification for Azure platforms
#[cfg(any(feature = "az-tdx", feature = "az-snp"))]
pub mod tpm_common;

#[cfg(feature = "az-tdx")]
pub mod az_tdx;

#[cfg(feature = "az-snp")]
pub mod az_snp;
