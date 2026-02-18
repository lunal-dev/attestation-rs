#[tokio::main]
async fn main() {
    let platform = attestation::detect().expect("no TEE platform detected");
    eprintln!("Detected platform: {}", platform.platform_type());

    let nonce = b"hello-attestation";
    let evidence_json = platform.attest_json(nonce).await.expect("attestation failed");
    println!("{}", String::from_utf8_lossy(&evidence_json));

    eprintln!("\nVerifying...");
    let params = attestation::VerifyParams::default();
    let result = platform
        .verify_json(&evidence_json, &params)
        .await
        .expect("verification failed");
    eprintln!("Signature valid: {}", result.signature_valid);
    eprintln!("Platform: {}", result.platform);
    eprintln!("Launch digest: {}", result.claims.launch_digest);
}
