use std::time::Instant;

#[tokio::main]
async fn main() {
    let custom_data: Vec<u8> = std::env::args()
        .nth(1)
        .map(|s| s.into_bytes())
        .unwrap_or_default();

    if custom_data.is_empty() {
        eprintln!("[mode] empty report_data");
    } else {
        eprintln!("[mode] custom report_data ({} bytes): {:?}", custom_data.len(), String::from_utf8_lossy(&custom_data));
    }

    // Step 1: generate evidence
    let t0 = Instant::now();
    let evidence = attestation::platforms::az_snp::attest::generate_evidence(&custom_data)
        .await
        .expect("generate_evidence failed");
    let t_attest = t0.elapsed();
    eprintln!("[attest]  {:?}", t_attest);

    // Step 2: serialize to JSON
    let t1 = Instant::now();
    let json = serde_json::to_string(&evidence).expect("serialize failed");
    let t_ser = t1.elapsed();
    eprintln!("[serialize] {:?} ({} bytes)", t_ser, json.len());

    // Step 3: verify the evidence
    let t2 = Instant::now();
    let params = attestation::types::VerifyParams::default();
    let provider = attestation::collateral::DefaultCertProvider::new();
    let result = attestation::platforms::az_snp::verify::verify_evidence(
        &evidence,
        &params,
        &provider,
    )
    .await
    .expect("verify failed");
    let t_verify = t2.elapsed();
    eprintln!("[verify]  {:?}", t_verify);

    let total = t0.elapsed();
    eprintln!("[total]   {:?}", total);
    eprintln!("[result]  sig_valid={} platform={}", result.signature_valid, result.platform);

    // Print JSON to stdout
    println!("{json}");
}
