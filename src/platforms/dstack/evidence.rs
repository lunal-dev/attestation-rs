use serde::{Deserialize, Serialize};

/// dstack TDX attestation evidence from a Phala CVM or similar dstack environment.
///
/// dstack proxies TDX attestation via a Unix domain socket, producing standard
/// Intel TDX v4/v5 quotes. The evidence wraps the TDX quote plus dstack-specific
/// metadata (event log and VM configuration).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DstackEvidence {
    /// Base64-encoded TDX quote bytes (standard Intel TDX v4/v5 format).
    pub quote: String,
    /// JSON-encoded event log from dstack (RTMR extensions), if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_log: Option<String>,
    /// VM configuration string from dstack, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vm_config: Option<String>,
}
