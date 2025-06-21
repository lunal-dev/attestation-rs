use std::fs;

use lunal_attestation::sev_snp::verify::verify_attestation as verify_snp_attestation;
use lunal_attestation::tdx::verify::verify_attestation;

async fn run_tdx_verification() -> Result<(), Box<dyn std::error::Error>> {
    let attestation_content = fs::read_to_string("example/attestation.txt")?;
    match verify_attestation(&attestation_content).await {
        Ok(result) => println!("Attestation verification successful: {:?}", result),
        Err(e) => eprintln!("Error verifying attestation: {}", e),
    }

    Ok(())
}

async fn run_sev_snp_verification() -> Result<(), Box<dyn std::error::Error>> {
    let attestation_content = fs::read_to_string("example/sev_snp_attestation.txt")?;
    match verify_snp_attestation(&attestation_content).await {
        Ok(result) => println!("Attestation verification successful: {:?}", result),
        Err(e) => eprintln!("Error verifying attestation: {}", e),
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    // if let Err(e) = run_tdx_verification().await {
    //     eprintln!("Error: {}", e);
    //     std::process::exit(1);
    // }

    if let Err(e) = run_sev_snp_verification().await {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
