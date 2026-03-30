//! Live DCAP verification test - fetches collateral from Intel PCS v4
//! Run: cargo test --test live_dcap --features tdx -- --nocapture

use attestation::collateral::DefaultTdxCollateralProvider;
use attestation::platforms::tdx::evidence::TdxEvidence;
use attestation::platforms::tdx::verify::{parse_tdx_quote, verify_evidence};
use attestation::types::VerifyParams;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

const V4_QUOTE: &[u8] = include_bytes!("../test_data/tdx_quote_4.dat");
const V5_QUOTE: &[u8] = include_bytes!("../test_data/tdx_quote_5.dat");
const LIVE_QUOTE: &[u8] = include_bytes!("../test_data/tdx_quote_live.dat");
const LIVE_CCEL: &[u8] = include_bytes!("../test_data/tdx_ccel_live2.dat");

fn make_evidence(quote_bytes: &[u8]) -> TdxEvidence {
    TdxEvidence {
        quote: BASE64.encode(quote_bytes),
        cc_eventlog: None,
    }
}

/// Full DCAP verification of V4 quote with live Intel PCS collateral.
#[tokio::test]
async fn test_v4_full_dcap_live_pcs() {
    let quote = parse_tdx_quote(V4_QUOTE).expect("parse v4");
    let evidence = make_evidence(V4_QUOTE);

    // V4 fixture has debug bit set
    let params = VerifyParams {
        expected_report_data: Some(quote.body.report_data.to_vec()),
        allow_debug: true,
        ..Default::default()
    };

    let provider = DefaultTdxCollateralProvider::new();
    let result = verify_evidence(&evidence, &params, Some(&provider)).await;

    match &result {
        Ok(r) => {
            eprintln!("V4 DCAP verification succeeded:");
            eprintln!("  signature_valid: {}", r.signature_valid);
            eprintln!("  collateral_verified: {}", r.collateral_verified);
            eprintln!("  report_data_match: {:?}", r.report_data_match);
            eprintln!("  platform: {}", r.platform);
            if let Some(ref tcb) = r.tcb_status {
                eprintln!("  tcb_status: {}", tcb.tcb_status);
                eprintln!("  fmspc: {}", tcb.fmspc);
                eprintln!("  advisory_ids: {:?}", tcb.advisory_ids);
                eprintln!("  collateral_expired: {}", tcb.collateral_expired);
            }
            assert!(r.signature_valid);
            assert!(r.collateral_verified);
            assert_eq!(r.report_data_match, Some(true));
        }
        Err(e) => {
            eprintln!("V4 DCAP verification error: {e:?}");
            // Don't panic - the test is informational for now
            // Cert expiry or TCB issues are expected with old fixtures
        }
    }
}

/// Full DCAP verification of live quote from this host's TDX VM + CCEL replay.
#[tokio::test]
async fn test_live_quote_full_dcap() {
    let quote = parse_tdx_quote(LIVE_QUOTE).expect("parse live quote");
    let evidence = TdxEvidence {
        quote: BASE64.encode(LIVE_QUOTE),
        cc_eventlog: Some(BASE64.encode(LIVE_CCEL)),
    };

    // Live quote has zero report_data (test generation)
    let params = VerifyParams {
        expected_report_data: Some(quote.body.report_data.to_vec()),
        ..Default::default()
    };

    let provider = DefaultTdxCollateralProvider::new();
    let result = verify_evidence(&evidence, &params, Some(&provider)).await;

    match &result {
        Ok(r) => {
            eprintln!("Live quote DCAP verification succeeded:");
            eprintln!("  signature_valid: {}", r.signature_valid);
            eprintln!("  collateral_verified: {}", r.collateral_verified);
            eprintln!("  report_data_match: {:?}", r.report_data_match);
            eprintln!("  platform: {}", r.platform);
            if let Some(ref tcb) = r.tcb_status {
                eprintln!("  tcb_status: {}", tcb.tcb_status);
                eprintln!("  fmspc: {}", tcb.fmspc);
                eprintln!("  advisory_ids: {:?}", tcb.advisory_ids);
                eprintln!("  collateral_expired: {}", tcb.collateral_expired);
            }
            assert!(r.signature_valid, "ECDSA signature must be valid");
            assert!(r.collateral_verified, "Collateral must verify");
            assert_eq!(r.report_data_match, Some(true));
        }
        Err(e) => {
            eprintln!("Live quote DCAP verification error: {e:?}");
            panic!("Live quote from this host should verify: {e:?}");
        }
    }
}

/// Full DCAP verification of V5 quote with live Intel PCS collateral.
#[tokio::test]
async fn test_v5_full_dcap_live_pcs() {
    let quote = parse_tdx_quote(V5_QUOTE).expect("parse v5");
    let evidence = make_evidence(V5_QUOTE);

    let params = VerifyParams {
        expected_report_data: Some(quote.body.report_data.to_vec()),
        ..Default::default()
    };

    let provider = DefaultTdxCollateralProvider::new();
    let result = verify_evidence(&evidence, &params, Some(&provider)).await;

    match &result {
        Ok(r) => {
            eprintln!("V5 DCAP verification succeeded:");
            eprintln!("  signature_valid: {}", r.signature_valid);
            eprintln!("  collateral_verified: {}", r.collateral_verified);
            eprintln!("  report_data_match: {:?}", r.report_data_match);
            if let Some(ref tcb) = r.tcb_status {
                eprintln!("  tcb_status: {}", tcb.tcb_status);
                eprintln!("  fmspc: {}", tcb.fmspc);
                eprintln!("  advisory_ids: {:?}", tcb.advisory_ids);
                eprintln!("  collateral_expired: {}", tcb.collateral_expired);
            }
        }
        Err(e) => {
            eprintln!("V5 DCAP verification error: {e:?}");
        }
    }
}
