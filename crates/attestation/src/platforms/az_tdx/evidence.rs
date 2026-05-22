use serde::{Deserialize, Serialize};

use crate::platforms::tpm_common::TpmQuote;

/// Azure TDX vTPM attestation evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzTdxEvidence {
    /// Evidence format version.
    pub version: u32,
    /// TPM attestation quote (shared with Azure SNP).
    pub tpm_quote: TpmQuote,
    /// HCL (Hardware Compatibility Layer) report, URL-safe base64 encoded.
    pub hcl_report: String,
    /// TD quote from Azure IMDS, URL-safe base64 encoded.
    pub td_quote: String,
}
