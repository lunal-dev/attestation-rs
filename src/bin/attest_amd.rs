use std::env;
use std::fs;

use lunal_attestation::amd_azure::AttestationEvidence;
#[cfg(feature = "attestation")]
use lunal_attestation::amd_azure::attest;
use lunal_attestation::amd_azure::verify::verify_evidence;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <attest|verify> [evidence_file]", args[0]);
        eprintln!("  attest: Generate attestation evidence");
        eprintln!("  verify <file>: Verify evidence from file");
        return Ok(());
    }

    match args[1].as_str() {
        #[cfg(feature = "attestation")]
        "attest" => {
            println!("Generating attestation evidence...");

            // Custom data to include in the attestation
            let custom_data = b"application-data";

            // Generate attestation evidence
            let evidence = attest::attest(custom_data).await?;

            // Serialize to bytes
            let evidence_bytes = evidence.to_bytes()?;

            // Print as hex bytes that can be copied
            println!("Evidence bytes (copy to file):");
            println!("{}", hex::encode(&evidence_bytes));

            // Also save to file for convenience
            fs::write("evidence.hex", hex::encode(&evidence_bytes))?;
            println!("Evidence saved to evidence.hex");

            // Show compressed base64 version too
            let compressed = attest::attest_compressed(custom_data).await?;
            println!("Compressed base64 evidence:");
            println!("{}", compressed);
        }

        "verify" => {
            if args.len() < 3 {
                eprintln!("Please provide evidence file path");
                return Ok(());
            }

            println!("Verifying attestation evidence...");

            // Read evidence from file (assuming hex format)
            let hex_data = fs::read_to_string(&args[2])?;
            let evidence_bytes = hex::decode(hex_data.trim())?;

            // Deserialize evidence
            let evidence = AttestationEvidence::from_bytes(&evidence_bytes)?;
            // The same custom data used during attestation
            let custom_data = b"my-application-nonce-12345";

            // Verify the evidence
            match verify_evidence(custom_data, &evidence).await {
                Ok(verification_result) => {
                    println!("✅ Attestation evidence verified successfully!");
                    // println!("\nVerification Results:");
                    // println!(
                    //     "Quote: {}",
                    //     serde_json::to_string_pretty(&verification_result.quote)?
                    // );
                    // println!(
                    //     "Report: {}",
                    //     serde_json::to_string_pretty(&verification_result.report)?
                    // );
                    // println!(
                    //     "Certs: {}",
                    //     serde_json::to_string_pretty(&verification_result.certs)?
                    // );
                    // println!("Report Data: {}", verification_result.report_data);
                }
                Err(e) => println!("❌ Verification failed: {}", e),
            }
        }

        _ => {
            eprintln!("Unknown command: {}", args[1]);
            eprintln!("Use 'attest' or 'verify'");
        }
    }

    Ok(())
}
