//! Utility to capture live attestation evidence and save as test fixture.
//! Run with: cargo test --test capture_fixture --features "all-platforms,attest" -- --ignored --nocapture

#![cfg(feature = "attest")]

use attestation::platforms::az_snp::AzSnp;
use attestation::platforms::Platform;

#[tokio::test]
#[ignore]
async fn capture_az_snp_evidence_fixture() {
    let az_snp = AzSnp::with_default_provider();
    let nonce = b"attestation-test-fixture";
    let evidence = az_snp.attest(nonce).await.expect("attest failed");

    let json = serde_json::to_string_pretty(&evidence).unwrap();
    let path = "test_data/az_snp/live-evidence.json";
    std::fs::write(path, &json).unwrap();
    eprintln!("Wrote {} ({} bytes)", path, json.len());

    // Also verify it
    let params = attestation::types::VerifyParams::default();
    let result = az_snp
        .verify(&evidence, &params)
        .await
        .expect("verify failed");
    eprintln!(
        "Verified: signature_valid={}, platform={}",
        result.signature_valid, result.platform
    );
    eprintln!("Launch digest: {}", result.claims.launch_digest);
    assert!(result.signature_valid);
}
