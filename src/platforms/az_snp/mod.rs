pub mod evidence;
pub mod verify;

#[cfg(feature = "attest")]
pub mod attest;

use async_trait::async_trait;

use crate::error::Result;
use crate::platforms::Platform;
use crate::types::{PlatformType, VerificationResult, VerifyParams};
use evidence::AzSnpEvidence;

/// Azure SEV-SNP vTPM platform implementation.
pub struct AzSnp {
    pub(crate) cert_provider: std::sync::Arc<dyn crate::collateral::CertProvider>,
}

impl AzSnp {
    pub fn new(cert_provider: std::sync::Arc<dyn crate::collateral::CertProvider>) -> Self {
        Self { cert_provider }
    }

    pub fn with_default_provider() -> Self {
        Self {
            cert_provider: std::sync::Arc::new(crate::collateral::DefaultCertProvider::new()),
        }
    }
}

#[async_trait]
impl Platform for AzSnp {
    type Evidence = AzSnpEvidence;

    fn platform_type(&self) -> PlatformType {
        PlatformType::AzSnp
    }

    #[cfg(feature = "attest")]
    async fn attest(&self, report_data: &[u8]) -> Result<AzSnpEvidence> {
        attest::generate_evidence(report_data).await
    }

    async fn verify(
        &self,
        evidence: &AzSnpEvidence,
        params: &VerifyParams,
    ) -> Result<VerificationResult> {
        verify::verify_evidence(evidence, params, &*self.cert_provider).await
    }
}
