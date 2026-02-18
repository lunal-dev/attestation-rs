pub mod evidence;
pub mod verify;
pub mod claims;
pub mod certs;

#[cfg(feature = "attest")]
pub mod attest;

use async_trait::async_trait;

use crate::error::Result;
use crate::platforms::Platform;
use crate::types::{PlatformType, VerificationResult, VerifyParams};
use evidence::SnpEvidence;

/// AMD SEV-SNP bare-metal platform implementation.
pub struct Snp {
    pub(crate) cert_provider: std::sync::Arc<dyn crate::collateral::CertProvider>,
}

impl Snp {
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
impl Platform for Snp {
    type Evidence = SnpEvidence;

    fn platform_type(&self) -> PlatformType {
        PlatformType::Snp
    }

    #[cfg(feature = "attest")]
    async fn attest(&self, report_data: &[u8]) -> Result<SnpEvidence> {
        attest::generate_evidence(report_data).await
    }

    async fn verify(
        &self,
        evidence: &SnpEvidence,
        params: &VerifyParams,
    ) -> Result<VerificationResult> {
        verify::verify_evidence(evidence, params, &*self.cert_provider).await
    }
}
