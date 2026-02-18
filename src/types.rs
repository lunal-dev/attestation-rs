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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_type_display() {
        assert_eq!(PlatformType::Tdx.to_string(), "tdx");
        assert_eq!(PlatformType::Snp.to_string(), "snp");
        assert_eq!(PlatformType::AzTdx.to_string(), "az-tdx");
        assert_eq!(PlatformType::AzSnp.to_string(), "az-snp");
    }

    #[test]
    fn test_platform_type_display_all_variants() {
        // Ensure all variants produce non-empty display strings
        let variants = [
            PlatformType::Tdx,
            PlatformType::Snp,
            PlatformType::AzTdx,
            PlatformType::AzSnp,
        ];
        for v in &variants {
            let s = v.to_string();
            assert!(!s.is_empty(), "{:?} should have non-empty display", v);
        }
    }

    #[test]
    fn test_platform_type_serialization_roundtrip() {
        let original = PlatformType::Snp;
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: PlatformType = serde_json::from_str(&json).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_platform_type_all_variants_serialize() {
        for platform in &[
            PlatformType::Tdx,
            PlatformType::Snp,
            PlatformType::AzTdx,
            PlatformType::AzSnp,
        ] {
            let json = serde_json::to_string(platform).unwrap();
            let back: PlatformType = serde_json::from_str(&json).unwrap();
            assert_eq!(*platform, back);
        }
    }

    #[test]
    fn test_verify_params_default() {
        let params = VerifyParams::default();
        assert!(params.expected_report_data.is_none());
        assert!(params.expected_init_data_hash.is_none());
    }

    #[test]
    fn test_verify_params_with_report_data() {
        let params = VerifyParams {
            expected_report_data: Some(vec![0xAA; 32]),
            expected_init_data_hash: None,
        };
        assert!(params.expected_report_data.is_some());
        assert_eq!(params.expected_report_data.unwrap().len(), 32);
    }

    #[test]
    fn test_verify_params_with_both_fields() {
        let params = VerifyParams {
            expected_report_data: Some(vec![0xAA; 64]),
            expected_init_data_hash: Some(vec![0xBB; 32]),
        };
        assert!(params.expected_report_data.is_some());
        assert!(params.expected_init_data_hash.is_some());
    }

    #[test]
    fn test_processor_generation_from_cpuid() {
        // Milan range: family 0x19, model 0x00..0x0F
        assert_eq!(
            ProcessorGeneration::from_cpuid(0x19, 0x00),
            Some(ProcessorGeneration::Milan)
        );
        assert_eq!(
            ProcessorGeneration::from_cpuid(0x19, 0x0F),
            Some(ProcessorGeneration::Milan)
        );

        // Genoa range: family 0x19, model 0x10..0x1F or 0xA0..0xAF
        assert_eq!(
            ProcessorGeneration::from_cpuid(0x19, 0x10),
            Some(ProcessorGeneration::Genoa)
        );
        assert_eq!(
            ProcessorGeneration::from_cpuid(0x19, 0x1F),
            Some(ProcessorGeneration::Genoa)
        );
        assert_eq!(
            ProcessorGeneration::from_cpuid(0x19, 0xA0),
            Some(ProcessorGeneration::Genoa)
        );
        assert_eq!(
            ProcessorGeneration::from_cpuid(0x19, 0xAF),
            Some(ProcessorGeneration::Genoa)
        );

        // Turin range: family 0x1A, model 0x00..0x11
        assert_eq!(
            ProcessorGeneration::from_cpuid(0x1A, 0x00),
            Some(ProcessorGeneration::Turin)
        );
        assert_eq!(
            ProcessorGeneration::from_cpuid(0x1A, 0x11),
            Some(ProcessorGeneration::Turin)
        );

        // Unknown combinations
        assert_eq!(ProcessorGeneration::from_cpuid(0x00, 0x00), None);
        assert_eq!(ProcessorGeneration::from_cpuid(0xFF, 0xFF), None);
        assert_eq!(ProcessorGeneration::from_cpuid(0x18, 0x01), None);
        assert_eq!(ProcessorGeneration::from_cpuid(0x19, 0x20), None); // Gap between Milan/Genoa
        assert_eq!(ProcessorGeneration::from_cpuid(0x1A, 0x12), None); // Just past Turin range
    }

    #[test]
    fn test_processor_generation_product_name() {
        assert_eq!(ProcessorGeneration::Milan.product_name(), "Milan");
        assert_eq!(ProcessorGeneration::Genoa.product_name(), "Genoa");
        assert_eq!(ProcessorGeneration::Turin.product_name(), "Turin");
    }

    #[test]
    fn test_processor_generation_serialization_roundtrip() {
        for gen in &[
            ProcessorGeneration::Milan,
            ProcessorGeneration::Genoa,
            ProcessorGeneration::Turin,
        ] {
            let json = serde_json::to_string(gen).unwrap();
            let back: ProcessorGeneration = serde_json::from_str(&json).unwrap();
            assert_eq!(*gen, back);
        }
    }

    #[test]
    fn test_snp_tcb_fields() {
        let tcb = SnpTcb {
            bootloader: 3,
            tee: 0,
            snp: 8,
            microcode: 115,
        };
        assert_eq!(tcb.bootloader, 3);
        assert_eq!(tcb.tee, 0);
        assert_eq!(tcb.snp, 8);
        assert_eq!(tcb.microcode, 115);
    }

    #[test]
    fn test_snp_tcb_serialization_roundtrip() {
        let tcb = SnpTcb {
            bootloader: 3,
            tee: 0,
            snp: 8,
            microcode: 115,
        };
        let json = serde_json::to_string(&tcb).unwrap();
        let back: SnpTcb = serde_json::from_str(&json).unwrap();
        assert_eq!(tcb, back);
    }

    #[test]
    fn test_claims_serialization_roundtrip() {
        // Create a Claims with SNP TCB
        let claims = Claims {
            launch_digest: "a1f3930413247bb38cfc171579ea3c12".to_string(),
            report_data: vec![0xAA; 64],
            init_data: vec![0xBB; 32],
            tcb: TcbInfo::Snp {
                bootloader: 3,
                tee: 0,
                snp: 8,
                microcode: 115,
            },
            platform_data: serde_json::json!({
                "vmpl": 0,
                "guest_svn": 4,
            }),
        };

        let json = serde_json::to_string(&claims).unwrap();
        let deserialized: Claims = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.launch_digest, claims.launch_digest);
        assert_eq!(deserialized.report_data, claims.report_data);
        assert_eq!(deserialized.init_data, claims.init_data);
        assert_eq!(deserialized.platform_data, claims.platform_data);

        match &deserialized.tcb {
            TcbInfo::Snp {
                bootloader,
                tee,
                snp,
                microcode,
            } => {
                assert_eq!(*bootloader, 3);
                assert_eq!(*tee, 0);
                assert_eq!(*snp, 8);
                assert_eq!(*microcode, 115);
            }
            other => panic!("expected TcbInfo::Snp, got: {:?}", other),
        }
    }

    #[test]
    fn test_claims_tdx_serialization_roundtrip() {
        // Create a Claims with TDX TCB
        let claims = Claims {
            launch_digest: "dfba221b48a22af8511542ee796603f3".to_string(),
            report_data: vec![0xCC; 64],
            init_data: vec![0x00; 48],
            tcb: TcbInfo::Tdx {
                tcb_svn: vec![0x03, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            },
            platform_data: serde_json::json!({
                "quote_version": "V4",
                "tee_type": "0x81",
            }),
        };

        let json = serde_json::to_string(&claims).unwrap();
        let deserialized: Claims = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.launch_digest, claims.launch_digest);
        assert_eq!(deserialized.report_data, claims.report_data);
        assert_eq!(deserialized.init_data, claims.init_data);

        match &deserialized.tcb {
            TcbInfo::Tdx { tcb_svn } => {
                assert_eq!(tcb_svn.len(), 16);
                assert_eq!(tcb_svn[0], 0x03);
                assert_eq!(tcb_svn[2], 0x05);
            }
            other => panic!("expected TcbInfo::Tdx, got: {:?}", other),
        }
    }

    #[test]
    fn test_verification_result_serialization_roundtrip() {
        let result = VerificationResult {
            signature_valid: true,
            platform: PlatformType::Snp,
            claims: Claims {
                launch_digest: "abcdef".to_string(),
                report_data: vec![0x01, 0x02],
                init_data: vec![0x03, 0x04],
                tcb: TcbInfo::Snp {
                    bootloader: 1,
                    tee: 2,
                    snp: 3,
                    microcode: 4,
                },
                platform_data: serde_json::json!({}),
            },
            report_data_match: Some(true),
            init_data_match: Some(false),
        };

        let json = serde_json::to_string(&result).unwrap();
        let back: VerificationResult = serde_json::from_str(&json).unwrap();

        assert!(back.signature_valid);
        assert_eq!(back.platform, PlatformType::Snp);
        assert_eq!(back.report_data_match, Some(true));
        assert_eq!(back.init_data_match, Some(false));
        assert_eq!(back.claims.launch_digest, "abcdef");
    }

    #[test]
    fn test_verification_result_none_matches() {
        let result = VerificationResult {
            signature_valid: false,
            platform: PlatformType::Tdx,
            claims: Claims {
                launch_digest: String::new(),
                report_data: vec![],
                init_data: vec![],
                tcb: TcbInfo::Tdx { tcb_svn: vec![] },
                platform_data: serde_json::json!(null),
            },
            report_data_match: None,
            init_data_match: None,
        };

        let json = serde_json::to_string(&result).unwrap();
        let back: VerificationResult = serde_json::from_str(&json).unwrap();

        assert!(!back.signature_valid);
        assert_eq!(back.report_data_match, None);
        assert_eq!(back.init_data_match, None);
    }

    #[test]
    fn test_tcb_info_tagged_serialization() {
        // TcbInfo uses #[serde(tag = "type")] so the JSON should contain a "type" field
        let snp_tcb = TcbInfo::Snp {
            bootloader: 1,
            tee: 2,
            snp: 3,
            microcode: 4,
        };
        let json = serde_json::to_string(&snp_tcb).unwrap();
        assert!(
            json.contains("\"type\":\"Snp\""),
            "SNP TCB JSON should contain type tag: {}",
            json
        );

        let tdx_tcb = TcbInfo::Tdx {
            tcb_svn: vec![0x01, 0x02],
        };
        let json = serde_json::to_string(&tdx_tcb).unwrap();
        assert!(
            json.contains("\"type\":\"Tdx\""),
            "TDX TCB JSON should contain type tag: {}",
            json
        );
    }
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
