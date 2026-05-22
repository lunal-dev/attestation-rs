use serde::{Deserialize, Serialize};

use crate::platforms::tpm_common::TpmQuote;

/// Azure SEV-SNP vTPM attestation evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzSnpEvidence {
    /// Evidence format version.
    pub version: u32,
    /// TPM attestation quote.
    pub tpm_quote: TpmQuote,
    /// HCL (Hardware Compatibility Layer) report, URL-safe base64 encoded.
    pub hcl_report: String,
    /// VCEK certificate (DER), URL-safe base64 encoded.
    pub vcek: String,
}
