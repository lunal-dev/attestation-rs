use serde::{Deserialize, Serialize};

/// TDX attestation evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TdxEvidence {
    /// Base64-encoded TDX quote bytes.
    pub quote: String,
    /// Base64-encoded CC eventlog (CCEL/ACPI), if available.
    #[serde(default)]
    pub cc_eventlog: Option<String>,
}
