//! Utility to capture live attestation evidence and save as test fixture.
//! Run with: cargo test --test capture_fixture --features "attest" -- --ignored --nocapture

#![cfg(feature = "attest")]

#[tokio::test]
#[ignore]
async fn capture_az_snp_evidence_fixture() {
    let nonce = b"attestation-test-fixture";
    let evidence = attestation::platforms::az_snp::attest::generate_evidence(nonce)
        .await
        .expect("attest failed");

    let json = serde_json::to_string_pretty(&evidence).unwrap();
    let path = "test_data/az_snp/live-evidence.json";
    std::fs::write(path, &json).unwrap();
    eprintln!("Wrote {} ({} bytes)", path, json.len());

    // Also verify it
    let params = attestation::types::VerifyParams::default();
    let provider = attestation::collateral::DefaultCertProvider::new();
    let result =
        attestation::platforms::az_snp::verify::verify_evidence(&evidence, &params, &provider)
            .await
            .expect("verify failed");
    eprintln!(
        "Verified: signature_valid={}, platform={}",
        result.signature_valid, result.platform
    );
    eprintln!("Launch digest: {}", result.claims.launch_digest);
    assert!(result.signature_valid);
}

#[tokio::test]
#[ignore]
async fn capture_az_tdx_evidence_fixture() {
    let nonce = b"attestation-test-fixture";
    let evidence = attestation::platforms::az_tdx::attest::generate_evidence(nonce)
        .await
        .expect("attest failed");

    let json = serde_json::to_string_pretty(&evidence).unwrap();
    let path = "test_data/az_tdx/live-evidence.json";
    std::fs::write(path, &json).unwrap();
    eprintln!("Wrote {} ({} bytes)", path, json.len());

    // Also verify it
    let params = attestation::types::VerifyParams::default();
    let result = attestation::platforms::az_tdx::verify::verify_evidence(&evidence, &params, None)
        .await
        .expect("verify failed");
    eprintln!(
        "Verified: signature_valid={}, platform={}",
        result.signature_valid, result.platform
    );
    eprintln!("Launch digest: {}", result.claims.launch_digest);
    assert!(result.signature_valid);
}
