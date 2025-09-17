use std::fs;

mod pcs_client;
mod utils;

use lunal_attestation::verify::verify_attestation;

async fn run_verification() -> Result<(), Box<dyn std::error::Error>> {
    let attestation_content = fs::read_to_string("example/attestation.txt")?;
    match verify_attestation(&attestation_content).await {
        Ok(result) => println!("Attestation verification successful: {:?}", result),
        Err(e) => eprintln!("Error verifying attestation: {}", e),
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(e) = run_verification().await {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
