//! Azure SNP (vTPM) attestation example.
//!
//! Run on an Azure SNP Confidential VM:
//!   cargo run --example az_snp --features "az-snp,attest"

use std::env;
use std::time::Instant;

use attestation::{PlatformType, VerifyParams};

#[tokio::main]
async fn main() {
    let nonce: Vec<u8> = env::args()
        .nth(1)
        .map(|s| s.into_bytes())
        .unwrap_or_else(|| b"example-az-snp-nonce".to_vec());

    eprintln!("Nonce: {:?}", String::from_utf8_lossy(&nonce));

    let t0 = Instant::now();

    eprintln!("Generating Azure SNP attestation evidence...");
    let evidence_json = attestation::attest(PlatformType::AzSnp, &nonce)
        .await
        .expect("attestation failed");
    eprintln!(
        "[attest]  {:?} ({} bytes)",
        t0.elapsed(),
        evidence_json.len()
    );

    eprintln!("Verifying...");
    let t1 = Instant::now();
    let params = VerifyParams::default();
    let result = attestation::verify(&evidence_json, &params)
        .await
        .expect("verification failed");
    eprintln!("[verify]  {:?}", t1.elapsed());

    eprintln!("[total]   {:?}", t0.elapsed());
    eprintln!("Signature valid: {}", result.signature_valid);
    eprintln!("Platform: {}", result.platform);
    eprintln!("Launch digest: {}", result.claims.launch_digest);

    println!("{}", String::from_utf8_lossy(&evidence_json));
}
