//! Bare-metal AMD SEV-SNP attestation example.
//!
//! Run on an SNP-enabled machine:
//!   cargo run --example snp --features "snp,attest"

use attestation::{PlatformType, VerifyParams};

#[tokio::main]
async fn main() {
    let nonce = b"example-snp-nonce";

    eprintln!("Generating SNP attestation evidence...");
    let evidence_json = attestation::attest(PlatformType::Snp, nonce, &attestation::AttestOptions::default())
        .await
        .expect("attestation failed");

    eprintln!("Evidence: {} bytes", evidence_json.len());

    eprintln!("Verifying...");
    let params = VerifyParams::default();
    let result = attestation::verify(&evidence_json, &params)
        .await
        .expect("verification failed");

    eprintln!("Signature valid: {}", result.signature_valid);
    eprintln!("Platform: {}", result.platform);
    eprintln!("Launch digest: {}", result.claims.launch_digest);
    println!("{}", String::from_utf8_lossy(&evidence_json));
}
