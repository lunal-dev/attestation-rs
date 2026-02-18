use serde::{Deserialize, Serialize};

/// Platform identifier enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PlatformType {
    Tdx,
    Snp,
    AzTdx,
    AzSnp,
}

impl std::fmt::Display for PlatformType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlatformType::Tdx => write!(f, "tdx"),
            PlatformType::Snp => write!(f, "snp"),
            PlatformType::AzTdx => write!(f, "az-tdx"),
            PlatformType::AzSnp => write!(f, "az-snp"),
        }
    }
}

/// What the caller wants to check during verification.
#[derive(Debug, Clone, Default)]
pub struct VerifyParams {
    /// If set, verifier checks that report_data in the quote matches this value.
    pub expected_report_data: Option<Vec<u8>>,
    /// If set, verifier checks init_data / host_data / MRCONFIGID binding.
    pub expected_init_data_hash: Option<Vec<u8>>,
}

/// Result of verification — the caller decides pass/fail based on this.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Was the hardware signature on the evidence valid?
    pub signature_valid: bool,
    /// Which platform produced this evidence.
    pub platform: PlatformType,
    /// Parsed, platform-normalized claims.
    pub claims: Claims,
    /// Did the report_data match expected (None if no expected value provided).
    pub report_data_match: Option<bool>,
    /// Did the init_data match expected (None if no expected value provided).
    pub init_data_match: Option<bool>,
}

/// Normalized claims extracted from evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Hex-encoded launch measurement (MRTD for TDX, measurement for SNP).
    pub launch_digest: String,
    /// The report_data field from inside the HW quote, raw bytes.
    #[serde(with = "hex_bytes")]
    pub report_data: Vec<u8>,
    /// Init data / host data from the quote, raw bytes.
    #[serde(with = "hex_bytes")]
    pub init_data: Vec<u8>,
    /// TCB version information, platform-specific.
    pub tcb: TcbInfo,
    /// All platform-specific claim fields as a JSON map.
    pub platform_data: serde_json::Value,
}

/// TCB version information, varies by platform.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum TcbInfo {
    Snp {
        bootloader: u8,
        tee: u8,
        snp: u8,
        microcode: u8,
    },
    Tdx {
        /// Raw 16-byte TCB SVN from the quote body.
        #[serde(with = "hex_bytes")]
        tcb_svn: Vec<u8>,
    },
}

/// AMD processor generation for SNP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProcessorGeneration {
    Milan,
    Genoa,
    Turin,
}

impl ProcessorGeneration {
    /// Determine processor generation from CPUID family and model IDs.
    pub fn from_cpuid(family_id: u8, model_id: u8) -> Option<Self> {
        match (family_id, model_id) {
            (0x19, 0x00..=0x0F) => Some(ProcessorGeneration::Milan),
            (0x19, 0x10..=0x1F) | (0x19, 0xA0..=0xAF) => Some(ProcessorGeneration::Genoa),
            (0x1A, 0x00..=0x11) => Some(ProcessorGeneration::Turin),
            _ => None,
        }
    }

    /// Product name string used in AMD KDS URLs.
    pub fn product_name(&self) -> &'static str {
        match self {
            ProcessorGeneration::Milan => "Milan",
            ProcessorGeneration::Genoa => "Genoa",
            ProcessorGeneration::Turin => "Turin",
        }
    }
}

/// SNP TCB version components (used for KDS URL construction and TCB checks).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnpTcb {
    pub bootloader: u8,
    pub tee: u8,
    pub snp: u8,
    pub microcode: u8,
}

/// Helper module for serializing Vec<u8> as hex strings.
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}
