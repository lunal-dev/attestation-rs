use serde::{Deserialize, Serialize};

/// Raw SNP attestation evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnpEvidence {
    /// The raw attestation report bytes (1184 bytes), base64 encoded.
    pub attestation_report: String,
    /// Optional certificate chain from the hypervisor (VCEK/VLEK + ASK + ARK),
    /// each cert as base64-encoded DER.
    #[serde(default)]
    pub cert_chain: Option<SnpCertChain>,
}

/// Certificate chain provided by the hypervisor in the extended report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnpCertChain {
    /// VCEK or VLEK certificate (DER, base64 encoded).
    pub vcek: String,
    /// ASK certificate (DER, base64 encoded). Optional - use bundled if missing.
    #[serde(default)]
    pub ask: Option<String>,
    /// ARK certificate (DER, base64 encoded). Optional - use bundled if missing.
    #[serde(default)]
    pub ark: Option<String>,
}
