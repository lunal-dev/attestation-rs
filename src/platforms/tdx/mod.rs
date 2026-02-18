pub mod evidence;
pub mod verify;
pub mod claims;

#[cfg(feature = "attest")]
pub mod attest;

use async_trait::async_trait;

use crate::error::Result;
use crate::platforms::Platform;
use crate::types::{PlatformType, VerificationResult, VerifyParams};
use evidence::TdxEvidence;

/// Intel TDX bare-metal platform implementation.
pub struct Tdx;

impl Tdx {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Tdx {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Platform for Tdx {
    type Evidence = TdxEvidence;

    fn platform_type(&self) -> PlatformType {
        PlatformType::Tdx
    }

    #[cfg(feature = "attest")]
    async fn attest(&self, report_data: &[u8]) -> Result<TdxEvidence> {
        attest::generate_evidence(report_data).await
    }

    async fn verify(
        &self,
        evidence: &TdxEvidence,
        params: &VerifyParams,
    ) -> Result<VerificationResult> {
        verify::verify_evidence(evidence, params).await
    }
}
