use serde::{Deserialize, Serialize};

use crate::platforms::tpm_common::TpmQuote;

/// Bare-metal TPM 2.0 attestation evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmEvidence {
    /// Evidence format version (currently 1).
    pub version: u32,
    /// TPM attestation quote (signature, TPMS_ATTEST message, PCR values).
    pub tpm_quote: TpmQuote,
    /// AK public key as a TPM2B_PUBLIC structure, hex-encoded.
    pub ak_pub: String,
    /// EK certificate (DER), hex-encoded. Provides platform identity
    /// if the TPM manufacturer provisioned one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ek_cert: Option<String>,
}
