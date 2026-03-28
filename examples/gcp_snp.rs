//! GCP bare-metal AMD SEV-SNP attestation example.
//!
//! Run on a GCP Confidential VM with SEV-SNP:
//!   cargo run --example gcp_snp --features "gcp-snp,attest"

use attestation::{PlatformType, VerifyParams};

#[tokio::main]
async fn main() {
    let nonce = b"example-gcp-snp-nonce";

    eprintln!("Generating GCP SNP attestation evidence...");
    let evidence_json = attestation::attest(PlatformType::GcpSnp, nonce)
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
