//! KBS (Key Broker Service) compatible attestation evidence format.
//!
//! This module provides types and functions to convert attestation evidence
//! to the format expected by Confidential Containers Trustee KBS.
//!
//! ## azsnpvtpm (Azure vTPM)
//! For Azure CVMs with vTPM, KBS expects AzSnpVtpmEvidence with:
//! - quote: TPM Quote with signature, message, and PCR values
//! - report: Raw HCL report bytes
//! - vcek: PEM-encoded VCEK certificate string

use amd_vtpm::imds::Certificates;
use amd_vtpm::quote::Quote;
use serde::{Deserialize, Serialize};
use std::error::Error;

/// Azure SNP vTPM Evidence format expected by KBS/Trustee.
///
/// This matches the Evidence struct in:
/// https://github.com/confidential-containers/trustee/blob/main/deps/verifier/src/az_snp_vtpm/mod.rs
///
/// Used for Azure CVMs with vTPM attestation (TEE type: azsnpvtpm).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzSnpVtpmEvidence {
    /// TPM Quote containing signature, message, and PCR values
    pub quote: Quote,
    /// Raw HCL report bytes (includes SNP report + vTPM info)
    pub report: Vec<u8>,
    /// PEM-encoded VCEK certificate string
    pub vcek: String,
}

impl AzSnpVtpmEvidence {
    /// Create Azure vTPM evidence from TPM quote, HCL report, and certificates.
    pub fn new(quote: Quote, report: Vec<u8>, certs: &Certificates) -> Self {
        Self {
            quote,
            report,
            vcek: certs.vcek.clone(),
        }
    }

    /// Serialize to JSON string (KBS-compatible format).
    pub fn to_json(&self) -> Result<String, Box<dyn Error>> {
        Ok(serde_json::to_string(self)?)
    }
}

#[cfg(feature = "attestation")]
pub mod attest {
    use super::*;
    use amd_vtpm::{imds, vtpm};
    use base64::{engine::general_purpose::STANDARD, Engine};
    use canon_json::CanonicalFormatter;
    use serde::Serialize;
    use sha2::{Digest, Sha384};

    /// Serialize a value to canonical JSON format (RFC 8785).
    /// This uses the exact same canon-json crate as Trustee KBS.
    pub fn serialize_canon_json<T: Serialize>(
        value: &T,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut buf = Vec::new();
        let mut ser = serde_json::Serializer::with_formatter(&mut buf, CanonicalFormatter::new());
        value.serialize(&mut ser)?;
        Ok(buf)
    }

    /// Generate attestation evidence in Azure SNP vTPM format (azsnpvtpm).
    ///
    /// This is the correct format for Azure CVMs with vTPM attestation.
    /// The KBS verifier uses the TPM Quote to verify the attestation.
    ///
    /// The custom_data parameter is the base64-encoded runtime_data JSON from KBS.
    /// It contains the challenge nonce and TEE public key.
    ///
    /// KBS processes RuntimeData::Structured by:
    /// 1. Adding "additional-evidence" field from tee_evidence.additional_evidence
    /// 2. Canonical JSON serialization (keys in alphabetical order)
    /// 3. SHA384 hash of the serialized bytes
    /// 4. Passing the 48-byte hash as expected_report_data to the verifier
    ///
    /// We must match this by:
    /// 1. Parsing the runtime_data JSON
    /// 2. Adding "additional-evidence": "" (empty string for single TEE)
    /// 3. Re-serializing with alphabetically sorted keys (canonical form)
    /// 4. Hashing the canonical JSON with SHA384
    pub async fn attest_az_snp_vtpm(custom_data: &[u8]) -> Result<String, Box<dyn Error>> {
        // Decode the base64 runtime_data to get the raw JSON bytes
        // Parse, add additional-evidence field, canonicalize (RFC 8785), then hash with SHA384
        let nonce = if !custom_data.is_empty() {
            let runtime_data_json = STANDARD.decode(custom_data)?;

            // Parse JSON and add "additional-evidence" field to match KBS computation
            // KBS backend.rs adds this field from tee_evidence.additional_evidence
            // For single TEE attestation, this is always an empty string
            let mut value: serde_json::Value = serde_json::from_slice(&runtime_data_json)?;
            if let serde_json::Value::Object(ref mut map) = value {
                map.insert(
                    "additional-evidence".to_string(),
                    serde_json::Value::String(String::new()),
                );
            }

            // Re-serialize in canonical form (RFC 8785)
            // This uses the exact same canon-json crate as Trustee KBS
            let canonical_bytes = serialize_canon_json(&value)?;

            // Hash the canonical JSON with SHA384
            // SHA384 produces 48 bytes, which fits within TPM quote nonce limit (~64 bytes)
            let mut hasher = Sha384::new();
            hasher.update(&canonical_bytes);
            hasher.finalize().to_vec()
        } else {
            Vec::new()
        };

        // Get TPM Quote with the SHA384 hash as nonce
        // KBS verifier compares quote.nonce() with SHA384(canonical_json(runtime_data))
        let quote = vtpm::get_quote(&nonce)?;

        // Get raw HCL report (contains SNP measurements + vTPM AK public key)
        let report = vtpm::get_report()?;

        // Get certificates from Azure IMDS
        let certs = imds::get_certs().await?;

        // Create Azure vTPM evidence
        let evidence = AzSnpVtpmEvidence::new(quote, report, &certs);

        // Return as JSON
        evidence.to_json()
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "attestation")]
    mod attest_tests {
        use crate::amd::kbs::attest::serialize_canon_json;

        #[test]
        fn test_serialize_canon_json_sorts_keys() {
            // Input with keys in non-alphabetical order (Go struct order)
            let input = r#"{"nonce":"abc","tee-pubkey":{"kty":"EC","alg":"ES256","crv":"P-256","x":"xxx","y":"yyy"}}"#;
            let value: serde_json::Value = serde_json::from_str(input).unwrap();
            let canonical = serialize_canon_json(&value).unwrap();

            // Expected: keys sorted alphabetically at all levels (RFC 8785)
            // Top level: nonce < tee-pubkey (correct)
            // tee-pubkey: alg < crv < kty < x < y (alphabetical)
            let expected = r#"{"nonce":"abc","tee-pubkey":{"alg":"ES256","crv":"P-256","kty":"EC","x":"xxx","y":"yyy"}}"#;
            assert_eq!(String::from_utf8(canonical).unwrap(), expected);
        }

        #[test]
        fn test_serialize_canon_json_nested_objects() {
            let input = r#"{"z":{"b":1,"a":2},"a":{"y":3,"x":4}}"#;
            let value: serde_json::Value = serde_json::from_str(input).unwrap();
            let canonical = serialize_canon_json(&value).unwrap();

            // Keys sorted: a < z, and within each: a < b, x < y
            let expected = r#"{"a":{"x":4,"y":3},"z":{"a":2,"b":1}}"#;
            assert_eq!(String::from_utf8(canonical).unwrap(), expected);
        }

        #[test]
        fn test_serialize_canon_json_with_additional_evidence() {
            // Test that additional-evidence field is sorted correctly
            // KBS adds additional-evidence to runtime_data before hashing
            let input = r#"{"nonce":"test","tee-pubkey":{"kty":"EC","alg":"ES256"},"additional-evidence":""}"#;
            let value: serde_json::Value = serde_json::from_str(input).unwrap();
            let canonical = serialize_canon_json(&value).unwrap();

            // Expected: additional-evidence < nonce < tee-pubkey (alphabetical)
            // Within tee-pubkey: alg < kty
            let expected = r#"{"additional-evidence":"","nonce":"test","tee-pubkey":{"alg":"ES256","kty":"EC"}}"#;
            assert_eq!(String::from_utf8(canonical).unwrap(), expected);
        }
    }
}
