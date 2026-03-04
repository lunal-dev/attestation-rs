use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use scroll::Pread;

use crate::error::{AttestationError, Result};
use crate::types::{PlatformType, VerificationResult, VerifyParams};

use super::claims::extract_claims;
use super::evidence::TdxEvidence;

/// TDX Quote header (48 bytes).
#[derive(Debug, Clone)]
pub struct QuoteHeader {
    pub version: u16,
    pub att_key_type: u16,
    pub tee_type: u32,
    pub reserved: [u8; 2],
    pub vendor_id: [u8; 16],
    pub user_data: [u8; 20],
}

/// TDX Quote Report Body (v4/v5 compatible).
#[derive(Debug, Clone)]
pub struct TdxReportBody {
    pub tee_tcb_svn: [u8; 16],
    pub mr_seam: [u8; 48],
    pub mrsigner_seam: [u8; 48],
    pub seam_attributes: [u8; 8],
    pub td_attributes: [u8; 8],
    pub xfam: [u8; 8],
    pub mr_td: [u8; 48],
    pub mr_config_id: [u8; 48],
    pub mr_owner: [u8; 48],
    pub mr_owner_config: [u8; 48],
    pub rtmr_0: [u8; 48],
    pub rtmr_1: [u8; 48],
    pub rtmr_2: [u8; 48],
    pub rtmr_3: [u8; 48],
    pub report_data: [u8; 64],
}

/// Parsed TDX quote (supports v4 and v5 formats).
#[derive(Debug, Clone)]
pub struct TdxQuote {
    pub header: QuoteHeader,
    pub body: TdxReportBody,
    pub quote_version: QuoteVersion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuoteVersion {
    V4,
    V5Tdx10,
    V5Tdx15,
}

pub(crate) const QUOTE_HEADER_SIZE: usize = 48;
pub(crate) const REPORT_BODY_SIZE: usize = 584;

impl QuoteHeader {
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < QUOTE_HEADER_SIZE {
            return Err(AttestationError::QuoteParseFailed(format!(
                "quote header too short: {} bytes",
                data.len()
            )));
        }

        let version = data.pread_with::<u16>(0, scroll::LE)
            .map_err(|e| AttestationError::QuoteParseFailed(format!("version: {}", e)))?;
        let att_key_type = data.pread_with::<u16>(2, scroll::LE)
            .map_err(|e| AttestationError::QuoteParseFailed(format!("att_key_type: {}", e)))?;
        let tee_type = data.pread_with::<u32>(4, scroll::LE)
            .map_err(|e| AttestationError::QuoteParseFailed(format!("tee_type: {}", e)))?;

        let mut reserved = [0u8; 2];
        reserved.copy_from_slice(&data[8..10]);

        let mut vendor_id = [0u8; 16];
        vendor_id.copy_from_slice(&data[12..28]);

        let mut user_data = [0u8; 20];
        user_data.copy_from_slice(&data[28..48]);

        Ok(Self {
            version,
            att_key_type,
            tee_type,
            reserved,
            vendor_id,
            user_data,
        })
    }
}

impl TdxReportBody {
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < REPORT_BODY_SIZE {
            return Err(AttestationError::QuoteParseFailed(format!(
                "report body too short: {} bytes, expected {}",
                data.len(),
                REPORT_BODY_SIZE
            )));
        }

        let mut offset = 0;

        macro_rules! read_bytes {
            ($size:expr) => {{
                let mut buf = [0u8; $size];
                buf.copy_from_slice(&data[offset..offset + $size]);
                offset += $size;
                buf
            }};
        }

        let tee_tcb_svn = read_bytes!(16);
        let mr_seam = read_bytes!(48);
        let mrsigner_seam = read_bytes!(48);
        let seam_attributes = read_bytes!(8);
        let td_attributes = read_bytes!(8);
        let xfam = read_bytes!(8);
        let mr_td = read_bytes!(48);
        let mr_config_id = read_bytes!(48);
        let mr_owner = read_bytes!(48);
        let mr_owner_config = read_bytes!(48);
        let rtmr_0 = read_bytes!(48);
        let rtmr_1 = read_bytes!(48);
        let rtmr_2 = read_bytes!(48);
        let rtmr_3 = read_bytes!(48);
        let report_data = read_bytes!(64);
        let _ = offset; // suppress unused assignment warning from macro

        Ok(Self {
            tee_tcb_svn,
            mr_seam,
            mrsigner_seam,
            seam_attributes,
            td_attributes,
            xfam,
            mr_td,
            mr_config_id,
            mr_owner,
            mr_owner_config,
            rtmr_0,
            rtmr_1,
            rtmr_2,
            rtmr_3,
            report_data,
        })
    }
}

/// Parse a TDX quote from raw bytes. Supports v4 and v5 formats.
/// Expected TDX TEE type value in the quote header.
const TDX_TEE_TYPE: u32 = 0x81;

pub fn parse_tdx_quote(data: &[u8]) -> Result<TdxQuote> {
    let header = QuoteHeader::from_bytes(data)?;

    // Validate TEE type is TDX (0x81)
    if header.tee_type != TDX_TEE_TYPE {
        return Err(AttestationError::QuoteParseFailed(format!(
            "invalid TEE type: expected 0x{:02X} (TDX), got 0x{:02X}",
            TDX_TEE_TYPE, header.tee_type
        )));
    }

    match header.version {
        4 => {
            // v4: header (48) + body (584) + auth data
            let body = TdxReportBody::from_bytes(&data[QUOTE_HEADER_SIZE..])?;
            Ok(TdxQuote {
                header,
                body,
                quote_version: QuoteVersion::V4,
            })
        }
        5 => {
            // v5: header (48) + type (2) + size (4) + body
            if data.len() < QUOTE_HEADER_SIZE + 6 {
                return Err(AttestationError::QuoteParseFailed(
                    "v5 quote too short for type/size fields".to_string(),
                ));
            }

            let body_type = data.pread_with::<u16>(QUOTE_HEADER_SIZE, scroll::LE)
                .map_err(|e| AttestationError::QuoteParseFailed(format!("v5 type: {}", e)))?;
            let body_size = data.pread_with::<u32>(QUOTE_HEADER_SIZE + 2, scroll::LE)
                .map_err(|e| AttestationError::QuoteParseFailed(format!("v5 size: {}", e)))?
                as usize;

            // Validate body_size matches expected size for the body type
            let expected_body_size = match body_type {
                2 => REPORT_BODY_SIZE,       // TDX 1.0: 584 bytes
                3 => REPORT_BODY_SIZE + 64,  // TDX 1.5: 648 bytes (584 + 64 for TEE_TCB_SVN2)
                _ => 0, // will be caught below
            };
            if expected_body_size > 0 && body_size != expected_body_size {
                return Err(AttestationError::QuoteParseFailed(format!(
                    "v5 body_size {} does not match expected {} for type {}",
                    body_size, expected_body_size, body_type
                )));
            }

            let body_offset = QUOTE_HEADER_SIZE + 6;
            if data.len() < body_offset + body_size {
                return Err(AttestationError::QuoteParseFailed(format!(
                    "v5 quote too short: need {} bytes, have {}",
                    body_offset + body_size,
                    data.len()
                )));
            }

            let body = TdxReportBody::from_bytes(&data[body_offset..body_offset + body_size])?;

            let quote_version = match body_type {
                2 => QuoteVersion::V5Tdx10,  // TDX 1.0
                3 => QuoteVersion::V5Tdx15,  // TDX 1.5
                _ => {
                    return Err(AttestationError::QuoteParseFailed(format!(
                        "unknown v5 body type: {}",
                        body_type
                    )));
                }
            };

            Ok(TdxQuote {
                header,
                body,
                quote_version,
            })
        }
        v => Err(AttestationError::QuoteParseFailed(format!(
            "unsupported quote version: {}",
            v
        ))),
    }
}

/// Extract and verify the ECDSA P-256 quote signature.
///
/// The TDX quote auth data follows the report body and contains:
/// - sig_data_len (4 bytes LE)
/// - ECDSA P-256 signature (64 bytes: R[32] || S[32])
/// - ECDSA attestation public key (64 bytes: X[32] || Y[32])
/// - QE certification data (variable)
///
/// The signature covers SHA-256(header + body).
pub fn verify_quote_signature(quote_bytes: &[u8], quote: &TdxQuote) -> Result<bool> {
    // Determine where the body ends (and auth data begins)
    let body_end = super::dcap::compute_body_end(quote_bytes, quote.quote_version)?;

    // Need at least sig_data_len(4) + signature(64) + attest_key(64) = 132 bytes of auth data
    if quote_bytes.len() < body_end + 132 {
        return Err(AttestationError::QuoteParseFailed(
            "quote too short for auth data (signature + attestation key)".to_string(),
        ));
    }

    let sig_data_len = quote_bytes
        .pread_with::<u32>(body_end, scroll::LE)
        .map_err(|e| AttestationError::QuoteParseFailed(format!("sig_data_len: {}", e)))?
        as usize;

    if sig_data_len < 128 {
        return Err(AttestationError::QuoteParseFailed(format!(
            "sig_data_len too small: {} (need at least 128 for sig + key)",
            sig_data_len
        )));
    }

    // Extract ECDSA P-256 signature (64 bytes: R || S)
    let sig_offset = body_end + 4;
    let sig_r = &quote_bytes[sig_offset..sig_offset + 32];
    let sig_s = &quote_bytes[sig_offset + 32..sig_offset + 64];

    // Extract attestation public key (64 bytes: X || Y)
    let key_offset = sig_offset + 64;
    let key_x = &quote_bytes[key_offset..key_offset + 32];
    let key_y = &quote_bytes[key_offset + 32..key_offset + 64];

    // The signed data is the quote header + body
    let signed_data = &quote_bytes[..body_end];

    // Compute SHA-256 hash of the signed data
    let hash = crate::utils::sha256(signed_data);

    // Construct the ECDSA P-256 signature
    let mut r_arr = [0u8; 32];
    let mut s_arr = [0u8; 32];
    r_arr.copy_from_slice(sig_r);
    s_arr.copy_from_slice(sig_s);
    let signature = Signature::from_scalars(
        p256::FieldBytes::from(r_arr),
        p256::FieldBytes::from(s_arr),
    )
    .map_err(|e| {
        AttestationError::SignatureVerificationFailed(format!("construct P-256 sig: {}", e))
    })?;

    // Construct the verifying key from the uncompressed public key point
    // SEC1 uncompressed point format: 0x04 || X || Y
    let mut uncompressed = vec![0x04u8];
    uncompressed.extend_from_slice(key_x);
    uncompressed.extend_from_slice(key_y);

    let verifying_key = VerifyingKey::from_sec1_bytes(&uncompressed).map_err(|e| {
        AttestationError::SignatureVerificationFailed(format!("parse attestation key: {}", e))
    })?;

    // Verify: the signature is over the raw SHA-256 hash (pre-hashed)
    // DCAP signs SHA-256(header+body), so we need to use verify_prehash
    match verifying_key.verify_prehash(&hash, &signature) {
        Ok(()) => Ok(true),
        Err(e) => Err(AttestationError::SignatureVerificationFailed(format!(
            "ECDSA P-256 DCAP: {}",
            e
        ))),
    }
}

/// Verify TDX attestation evidence.
pub async fn verify_evidence(
    evidence: &TdxEvidence,
    params: &VerifyParams,
) -> Result<VerificationResult> {
    // 1. Decode the quote
    let quote_bytes = BASE64
        .decode(&evidence.quote)
        .map_err(|e| AttestationError::EvidenceDeserialize(format!("quote base64: {}", e)))?;

    // 2. Parse the quote
    let quote = parse_tdx_quote(&quote_bytes)?;

    // 3. DCAP ECDSA P-256 signature verification
    let sig_valid = verify_quote_signature(&quote_bytes, &quote)?;

    // 3b. Full DCAP chain verification: PCK cert chain → QE report sig → QE binding
    super::dcap::verify_dcap_chain(&quote_bytes, quote.quote_version, None)?;

    // 4. Check report_data binding
    let report_data_match = if let Some(expected) = &params.expected_report_data {
        let padded = crate::utils::pad_report_data(expected, 64)?;
        if !crate::utils::constant_time_eq(&quote.body.report_data, &padded) {
            return Err(AttestationError::ReportDataMismatch);
        }
        Some(true)
    } else {
        None
    };

    // 5. Check MRCONFIGID binding
    let init_data_match = if let Some(expected) = &params.expected_init_data_hash {
        let mut padded = vec![0u8; 48];
        let len = expected.len().min(48);
        padded[..len].copy_from_slice(&expected[..len]);
        if !crate::utils::constant_time_eq(&quote.body.mr_config_id, &padded) {
            return Err(AttestationError::InitDataMismatch);
        }
        Some(true)
    } else {
        None
    };

    // 6. Eventlog integrity check (if present)
    if evidence.cc_eventlog.is_some() {
        return Err(AttestationError::EventlogIntegrityFailed(
            "eventlog replay verification is not yet implemented; \
             cannot verify RTMR integrity against the eventlog"
                .to_string(),
        ));
    }

    // 7. Extract claims
    let claims = extract_claims(&quote);

    Ok(VerificationResult {
        signature_valid: sig_valid,
        platform: PlatformType::Tdx,
        claims,
        report_data_match,
        init_data_match,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Load real test fixtures at compile time
    const V4_QUOTE: &[u8] = include_bytes!("../../../test_data/tdx_quote_4.dat");
    const V5_QUOTE: &[u8] = include_bytes!("../../../test_data/tdx_quote_5.dat");

    #[test]
    fn test_parse_v4_quote() {
        let quote = parse_tdx_quote(V4_QUOTE).unwrap();
        assert_eq!(quote.header.version, 4);
        assert_eq!(quote.quote_version, QuoteVersion::V4);
        // TDX TEE type is 0x81
        assert_eq!(quote.header.tee_type, 0x81);
    }

    #[test]
    fn test_parse_v5_quote() {
        let quote = parse_tdx_quote(V5_QUOTE).unwrap();
        assert_eq!(quote.header.version, 5);
        assert!(matches!(
            quote.quote_version,
            QuoteVersion::V5Tdx10 | QuoteVersion::V5Tdx15
        ));
    }

    #[test]
    fn test_parse_empty_quote() {
        let data = vec![0u8; 10];
        assert!(parse_tdx_quote(&data).is_err());
    }

    #[test]
    fn test_parse_invalid_version() {
        let mut data = vec![0u8; 700];
        // Set version to 99
        data[0] = 99;
        assert!(parse_tdx_quote(&data).is_err());
    }

    // ---------------------------------------------------------------
    // Tests using real TDX quote fixtures
    // ---------------------------------------------------------------

    #[test]
    fn test_v4_quote_fields() {
        let quote = parse_tdx_quote(V4_QUOTE).expect("failed to parse v4 quote");

        // Header fields
        assert_eq!(quote.header.version, 4);
        assert_eq!(quote.header.att_key_type, 2); // ECDSA-256-with-P-256 curve
        assert_eq!(quote.header.tee_type, 0x81); // TDX TEE type
        assert_eq!(quote.quote_version, QuoteVersion::V4);

        // Vendor ID should be populated (Intel QE vendor ID)
        assert!(
            quote.header.vendor_id.iter().any(|&b| b != 0),
            "vendor_id should not be all zeroes"
        );
        // Check known vendor ID prefix
        assert_eq!(quote.header.vendor_id[0], 0x93);

        // mr_td should be non-zero (launch measurement)
        assert!(
            quote.body.mr_td.iter().any(|&b| b != 0),
            "mr_td should not be all zeroes"
        );

        // Check known mr_td prefix bytes
        assert_eq!(quote.body.mr_td[0], 0x70);
        assert_eq!(quote.body.mr_td[1], 0x5e);

        // report_data should be non-zero
        assert!(
            quote.body.report_data.iter().any(|&b| b != 0),
            "report_data should not be all zeroes"
        );
        // Check known report_data prefix
        assert_eq!(quote.body.report_data[0], 0x7c);
        assert_eq!(quote.body.report_data[1], 0x71);

        // tee_tcb_svn should be non-zero
        assert!(
            quote.body.tee_tcb_svn.iter().any(|&b| b != 0),
            "tee_tcb_svn should not be all zeroes"
        );
        // Check known tee_tcb_svn values
        assert_eq!(quote.body.tee_tcb_svn[0], 0x03);
        assert_eq!(quote.body.tee_tcb_svn[2], 0x05);

        // mr_config_id is all zeroes in this fixture
        assert!(
            quote.body.mr_config_id.iter().all(|&b| b == 0),
            "mr_config_id should be all zeroes in this test fixture"
        );

        // RTMR 0 and 1 should be non-zero
        assert!(
            quote.body.rtmr_0.iter().any(|&b| b != 0),
            "rtmr_0 should not be all zeroes"
        );
        assert!(
            quote.body.rtmr_1.iter().any(|&b| b != 0),
            "rtmr_1 should not be all zeroes"
        );

        // RTMR 2 and 3 are zeroes in this fixture
        assert!(
            quote.body.rtmr_2.iter().all(|&b| b == 0),
            "rtmr_2 should be all zeroes in test fixture"
        );
        assert!(
            quote.body.rtmr_3.iter().all(|&b| b == 0),
            "rtmr_3 should be all zeroes in test fixture"
        );
    }

    #[test]
    fn test_v5_quote_fields() {
        let quote = parse_tdx_quote(V5_QUOTE).expect("failed to parse v5 quote");

        // Header fields
        assert_eq!(quote.header.version, 5);
        assert_eq!(quote.header.att_key_type, 2);
        assert_eq!(quote.header.tee_type, 0x81);

        // V5 with body type 3 => TDX 1.5
        assert_eq!(quote.quote_version, QuoteVersion::V5Tdx15);

        // mr_td should be non-zero
        assert!(
            quote.body.mr_td.iter().any(|&b| b != 0),
            "mr_td should not be all zeroes"
        );
        // Check known mr_td prefix bytes for v5
        assert_eq!(quote.body.mr_td[0], 0xdf);
        assert_eq!(quote.body.mr_td[1], 0xba);

        // report_data should be non-zero
        assert!(
            quote.body.report_data.iter().any(|&b| b != 0),
            "report_data should not be all zeroes"
        );
        assert_eq!(quote.body.report_data[0], 0x6d);
        assert_eq!(quote.body.report_data[1], 0x6a);

        // tee_tcb_svn should be non-zero
        assert!(
            quote.body.tee_tcb_svn.iter().any(|&b| b != 0),
            "tee_tcb_svn should not be all zeroes"
        );
        assert_eq!(quote.body.tee_tcb_svn[0], 0x05);
        assert_eq!(quote.body.tee_tcb_svn[1], 0x01);
        assert_eq!(quote.body.tee_tcb_svn[2], 0x02);
    }

    #[test]
    fn test_v4_v5_format_consistency() {
        // Both v4 and v5 should parse their report body successfully
        // and produce structurally valid outputs
        let v4 = parse_tdx_quote(V4_QUOTE).expect("failed to parse v4 quote");
        let v5 = parse_tdx_quote(V5_QUOTE).expect("failed to parse v5 quote");

        // Both should have TDX TEE type
        assert_eq!(v4.header.tee_type, v5.header.tee_type);
        assert_eq!(v4.header.tee_type, 0x81);

        // Both should have same attestation key type
        assert_eq!(v4.header.att_key_type, v5.header.att_key_type);

        // Both should have non-zero mr_td
        assert!(v4.body.mr_td.iter().any(|&b| b != 0));
        assert!(v5.body.mr_td.iter().any(|&b| b != 0));

        // But the measurements should be different (different TDs)
        assert_ne!(v4.body.mr_td, v5.body.mr_td);

        // Both should have non-zero report_data
        assert!(v4.body.report_data.iter().any(|&b| b != 0));
        assert!(v5.body.report_data.iter().any(|&b| b != 0));

        // Report data should be different between the two quotes
        assert_ne!(v4.body.report_data, v5.body.report_data);

        // report body fields have consistent sizes
        assert_eq!(v4.body.tee_tcb_svn.len(), 16);
        assert_eq!(v5.body.tee_tcb_svn.len(), 16);
        assert_eq!(v4.body.mr_seam.len(), 48);
        assert_eq!(v5.body.mr_seam.len(), 48);
        assert_eq!(v4.body.mr_td.len(), 48);
        assert_eq!(v5.body.mr_td.len(), 48);
        assert_eq!(v4.body.report_data.len(), 64);
        assert_eq!(v5.body.report_data.len(), 64);
    }

    #[test]
    fn test_quote_truncation_header_only() {
        // A quote with only the header (48 bytes) but no body should fail
        let truncated = &V4_QUOTE[..QUOTE_HEADER_SIZE];
        let result = parse_tdx_quote(truncated);
        assert!(result.is_err(), "truncated quote with header only should fail");
    }

    #[test]
    fn test_quote_truncation_partial_body() {
        // A quote with header + partial body should fail
        let truncated = &V4_QUOTE[..QUOTE_HEADER_SIZE + 100];
        let result = parse_tdx_quote(truncated);
        assert!(
            result.is_err(),
            "truncated quote with partial body should fail"
        );
    }

    #[test]
    fn test_quote_truncation_one_byte_short() {
        // V4: header (48) + body (584) = 632 minimum
        // One byte short of a complete body
        let min_size = QUOTE_HEADER_SIZE + REPORT_BODY_SIZE;
        let truncated = &V4_QUOTE[..min_size - 1];
        let result = parse_tdx_quote(truncated);
        assert!(
            result.is_err(),
            "quote one byte short of minimum should fail"
        );
    }

    #[test]
    fn test_quote_truncation_exact_minimum_v4() {
        // V4: exactly header + body should parse OK
        let min_size = QUOTE_HEADER_SIZE + REPORT_BODY_SIZE;
        let truncated = &V4_QUOTE[..min_size];
        let result = parse_tdx_quote(truncated);
        assert!(
            result.is_ok(),
            "exact minimum v4 quote should parse: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_quote_truncation_v5_no_type_size() {
        // V5 needs header + type(2) + size(4) = 54 bytes minimum before body
        // Truncate to just the header
        let truncated = &V5_QUOTE[..QUOTE_HEADER_SIZE + 2]; // Has type but no size
        let result = parse_tdx_quote(truncated);
        assert!(
            result.is_err(),
            "v5 quote without size field should fail"
        );
    }

    #[test]
    fn test_quote_truncation_v5_no_body() {
        // V5 header + type + size but no body
        let truncated = &V5_QUOTE[..QUOTE_HEADER_SIZE + 6];
        let result = parse_tdx_quote(truncated);
        assert!(
            result.is_err(),
            "v5 quote without body should fail"
        );
    }

    #[test]
    fn test_quote_truncation_empty() {
        let result = parse_tdx_quote(&[]);
        assert!(result.is_err(), "empty quote should fail");
    }

    #[test]
    fn test_quote_truncation_single_byte() {
        let result = parse_tdx_quote(&[0x04]); // version=4 but nothing else
        assert!(result.is_err(), "single byte quote should fail");
    }

    #[test]
    fn test_v4_quote_header_user_data() {
        let quote = parse_tdx_quote(V4_QUOTE).expect("failed to parse v4 quote");
        // user_data is 20 bytes from the header
        assert_eq!(quote.header.user_data.len(), 20);
    }

    #[test]
    fn test_v5_body_type_is_tdx15() {
        // The v5 test fixture has body_type=3, which is TDX 1.5
        let quote = parse_tdx_quote(V5_QUOTE).expect("failed to parse v5 quote");
        assert_eq!(quote.quote_version, QuoteVersion::V5Tdx15);
    }

    #[test]
    fn test_v5_invalid_body_type() {
        // Create a v5 quote with an invalid body type
        let mut data = V5_QUOTE.to_vec();
        // body_type is at offset 48 (after header), set to invalid value 99
        data[48] = 99;
        data[49] = 0;
        let result = parse_tdx_quote(&data);
        assert!(
            result.is_err(),
            "v5 quote with invalid body type should fail"
        );
    }

    #[test]
    fn test_quote_header_from_bytes_too_short() {
        let data = vec![0u8; 20]; // Less than 48 bytes
        let result = QuoteHeader::from_bytes(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_report_body_from_bytes_too_short() {
        let data = vec![0u8; 100]; // Less than 584 bytes
        let result = TdxReportBody::from_bytes(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_dcap_signature_verification_v4() {
        // Verify the real ECDSA P-256 signature on the v4 quote
        let quote = parse_tdx_quote(V4_QUOTE).expect("failed to parse v4 quote");
        let result = verify_quote_signature(V4_QUOTE, &quote);
        assert!(
            result.is_ok(),
            "v4 DCAP sig verification should succeed: {:?}",
            result.err()
        );
        assert!(result.unwrap(), "v4 DCAP signature should be valid");
    }

    #[test]
    fn test_dcap_signature_verification_v5() {
        // Verify the real ECDSA P-256 signature on the v5 quote
        let quote = parse_tdx_quote(V5_QUOTE).expect("failed to parse v5 quote");
        let result = verify_quote_signature(V5_QUOTE, &quote);
        assert!(
            result.is_ok(),
            "v5 DCAP sig verification should succeed: {:?}",
            result.err()
        );
        assert!(result.unwrap(), "v5 DCAP signature should be valid");
    }

    #[test]
    fn test_dcap_signature_tamper_detection() {
        // Flip a byte in the quote body and verify the sig fails
        let mut tampered = V4_QUOTE.to_vec();
        tampered[100] ^= 0xFF; // Flip a byte in the report body
        let quote = parse_tdx_quote(&tampered).expect("parse should still work");
        let result = verify_quote_signature(&tampered, &quote);
        assert!(
            result.is_err(),
            "tampered quote should fail DCAP sig verification"
        );
    }

    #[test]
    fn test_dcap_signature_truncated_auth_data() {
        // Quote with just header + body but no auth data
        let body_end = QUOTE_HEADER_SIZE + REPORT_BODY_SIZE;
        let truncated = &V4_QUOTE[..body_end + 10]; // Some bytes but not enough
        let quote = parse_tdx_quote(truncated).expect("parse should work");
        let result = verify_quote_signature(truncated, &quote);
        assert!(
            result.is_err(),
            "truncated auth data should fail verification"
        );
    }

    // ---------------------------------------------------------------
    // verify_evidence report_data tests (bare TDX path)
    // ---------------------------------------------------------------

    fn make_tdx_evidence(quote_bytes: &[u8]) -> TdxEvidence {
        TdxEvidence {
            quote: BASE64.encode(quote_bytes),
            cc_eventlog: None,
        }
    }

    #[tokio::test]
    async fn test_verify_evidence_v4_no_expected_report_data() {
        let evidence = make_tdx_evidence(V4_QUOTE);
        let params = VerifyParams::default();
        let result = verify_evidence(&evidence, &params).await;
        assert!(result.is_ok(), "verify should succeed: {:?}", result.err());
        let result = result.unwrap();
        assert!(result.signature_valid);
        assert!(result.report_data_match.is_none(), "should be None when no expected value");
    }

    #[tokio::test]
    async fn test_verify_evidence_v4_matching_report_data() {
        // Extract the actual report_data from the v4 quote fixture
        let quote = parse_tdx_quote(V4_QUOTE).unwrap();
        let evidence = make_tdx_evidence(V4_QUOTE);

        // Pass the exact report_data from the quote — should match
        let params = VerifyParams {
            expected_report_data: Some(quote.body.report_data.to_vec()),
            ..Default::default()
        };
        let result = verify_evidence(&evidence, &params).await;
        assert!(result.is_ok(), "verify with matching report_data should succeed: {:?}", result.err());
        assert_eq!(result.unwrap().report_data_match, Some(true));
    }

    #[tokio::test]
    async fn test_verify_evidence_v4_wrong_report_data_fails() {
        let evidence = make_tdx_evidence(V4_QUOTE);

        // Pass wrong report_data — should fail with ReportDataMismatch
        let params = VerifyParams {
            expected_report_data: Some(vec![0xFF; 64]),
            ..Default::default()
        };
        let result = verify_evidence(&evidence, &params).await;
        assert!(result.is_err(), "verify with wrong report_data should fail");
        let err = format!("{:?}", result.err().unwrap());
        assert!(err.contains("ReportDataMismatch"), "error should be ReportDataMismatch, got: {}", err);
    }

    #[tokio::test]
    async fn test_verify_evidence_v4_partial_report_data_padded() {
        // For bare TDX, report_data is padded to 64 bytes. If the fixture has a
        // specific pattern, passing just the non-zero prefix should still match
        // (only if the rest of report_data in the quote is zero-padded).
        let quote = parse_tdx_quote(V4_QUOTE).unwrap();

        // Find where the non-zero data ends
        let last_nonzero = quote.body.report_data.iter().rposition(|&b| b != 0);
        if let Some(end) = last_nonzero {
            // If the rest after end+1 is all zeros, passing just the prefix should match
            let suffix_is_zeros = quote.body.report_data[end + 1..].iter().all(|&b| b == 0);
            if suffix_is_zeros && end < 63 {
                let prefix = &quote.body.report_data[..=end];
                let evidence = make_tdx_evidence(V4_QUOTE);
                let params = VerifyParams {
                    expected_report_data: Some(prefix.to_vec()),
                    ..Default::default()
                };
                let result = verify_evidence(&evidence, &params).await;
                assert!(result.is_ok(), "padded partial report_data should match: {:?}", result.err());
            }
        }
    }

    #[tokio::test]
    async fn test_verify_evidence_v5_matching_report_data() {
        let quote = parse_tdx_quote(V5_QUOTE).unwrap();
        let evidence = make_tdx_evidence(V5_QUOTE);

        let params = VerifyParams {
            expected_report_data: Some(quote.body.report_data.to_vec()),
            ..Default::default()
        };
        let result = verify_evidence(&evidence, &params).await;
        assert!(result.is_ok(), "v5 verify with matching report_data should succeed: {:?}", result.err());
        assert_eq!(result.unwrap().report_data_match, Some(true));
    }

    #[tokio::test]
    async fn test_verify_evidence_v5_wrong_report_data_fails() {
        let evidence = make_tdx_evidence(V5_QUOTE);

        let params = VerifyParams {
            expected_report_data: Some(vec![0x00; 64]),
            ..Default::default()
        };
        let result = verify_evidence(&evidence, &params).await;
        assert!(result.is_err(), "v5 verify with wrong report_data should fail");
    }

    #[tokio::test]
    async fn test_verify_evidence_report_data_too_large() {
        let evidence = make_tdx_evidence(V4_QUOTE);

        // 65 bytes exceeds the 64-byte limit
        let params = VerifyParams {
            expected_report_data: Some(vec![0xAA; 65]),
            ..Default::default()
        };
        let result = verify_evidence(&evidence, &params).await;
        assert!(result.is_err(), "65-byte report_data should be rejected");
    }
}
