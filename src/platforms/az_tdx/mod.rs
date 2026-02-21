pub mod evidence;
pub mod verify;

#[cfg(all(feature = "attest", target_os = "linux"))]
pub mod attest;

use async_trait::async_trait;

use crate::error::Result;
use crate::platforms::Platform;
use crate::types::{PlatformType, VerificationResult, VerifyParams};
use evidence::AzTdxEvidence;

/// Azure TDX vTPM platform implementation.
pub struct AzTdx;

impl AzTdx {
    pub fn new() -> Self {
        Self
    }
}

impl Default for AzTdx {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Platform for AzTdx {
    type Evidence = AzTdxEvidence;

    fn platform_type(&self) -> PlatformType {
        PlatformType::AzTdx
    }

    #[cfg(all(feature = "attest", target_os = "linux"))]
    async fn attest(&self, report_data: &[u8]) -> Result<AzTdxEvidence> {
        attest::generate_evidence(report_data).await
    }

    async fn verify(
        &self,
        evidence: &AzTdxEvidence,
        params: &VerifyParams,
    ) -> Result<VerificationResult> {
        verify::verify_evidence(evidence, params).await
    }
}
