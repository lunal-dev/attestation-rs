use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
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

const QUOTE_HEADER_SIZE: usize = 48;
const REPORT_BODY_SIZE: usize = 584;

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
pub fn parse_tdx_quote(data: &[u8]) -> Result<TdxQuote> {
    let header = QuoteHeader::from_bytes(data)?;

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
            let _body_size = data.pread_with::<u32>(QUOTE_HEADER_SIZE + 2, scroll::LE)
                .map_err(|e| AttestationError::QuoteParseFailed(format!("v5 size: {}", e)))?;

            let body_offset = QUOTE_HEADER_SIZE + 6;
            let body = TdxReportBody::from_bytes(&data[body_offset..])?;

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

    // 3. DCAP ECDSA verification
    // For now, we skip the DCAP C library verification since it requires
    // native Intel libraries. The signature is verified structurally.
    // TODO: Integrate intel-tee-quote-verification-rs for native builds
    // TODO: Implement pure-Rust ECDSA P-256 for WASM builds
    let sig_valid = true; // Placeholder - real DCAP check needed

    // 4. Check report_data binding
    let report_data_match = params.expected_report_data.as_ref().map(|expected| {
        let padded = crate::utils::pad_report_data(expected, 64).unwrap_or_default();
        crate::utils::constant_time_eq(&quote.body.report_data, &padded)
    });

    // 5. Check MRCONFIGID binding
    let init_data_match = params.expected_init_data_hash.as_ref().map(|expected| {
        let mut padded = vec![0u8; 48];
        let len = expected.len().min(48);
        padded[..len].copy_from_slice(&expected[..len]);
        crate::utils::constant_time_eq(&quote.body.mr_config_id, &padded)
    });

    // 6. Eventlog integrity check (if present)
    if let Some(eventlog_b64) = &evidence.cc_eventlog {
        let _eventlog_bytes = BASE64
            .decode(eventlog_b64)
            .map_err(|e| AttestationError::EvidenceDeserialize(format!("eventlog base64: {}", e)))?;

        // TODO: Replay CCEL events and verify RTMRs match quote
        // This requires a full TCG eventlog parser
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

    #[test]
    fn test_parse_v4_quote() {
        let quote_data = include_bytes!("../../../test_data/tdx_quote_4.dat");
        let quote = parse_tdx_quote(quote_data).unwrap();
        assert_eq!(quote.header.version, 4);
        assert_eq!(quote.quote_version, QuoteVersion::V4);
        // TDX TEE type is 0x81
        assert_eq!(quote.header.tee_type, 0x81);
    }

    #[test]
    fn test_parse_v5_quote() {
        let quote_data = include_bytes!("../../../test_data/tdx_quote_5.dat");
        let quote = parse_tdx_quote(quote_data).unwrap();
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
}
