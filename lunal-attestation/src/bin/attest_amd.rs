use std::env;
use std::fs;

use lunal_attestation::amd_azure::AttestationEvidence;
#[cfg(feature = "attestation")]
use lunal_attestation::amd_azure::attest;
use lunal_attestation::amd_azure::verify::verify_compressed;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!(
            "Usage: {} <attest|verify> [evidence_file] [custom_data]",
            args[0]
        );
        eprintln!("  attest [custom_data]: Generate attestation evidence");
        eprintln!("  verify <file> [custom_data]: Verify evidence from file");
        return Ok(());
    }

    // Get custom data from args or use empty
    let custom_data = if args.len() > 3 {
        args[3].as_bytes()
    } else if args.len() > 2 && args[1] == "attest" {
        args[2].as_bytes()
    } else {
        b""
    };

    match args[1].as_str() {
        #[cfg(feature = "attestation")]
        "attest" => {
            // Generate attestation evidence (compressed and base64 encoded)
            let evidence_string = attest::attest_compressed(custom_data).await?;

            // Print the base64 string that can be copied
            println!("{}", evidence_string);
            fs::write("evidence.b64", &evidence_string)?;
        }

        "verify" => {
            if args.len() < 3 {
                eprintln!("Please provide evidence file path");
                return Ok(());
            }

            println!("Verifying attestation evidence...");

            // Read evidence from file (assuming base64 compressed format)
            let evidence_string = fs::read_to_string(&args[2])?;

            if !custom_data.is_empty() {
                println!(
                    "Using custom data: {}",
                    String::from_utf8_lossy(custom_data)
                );
            } else {
                println!("Using empty custom data");
            }

            // Verify the evidence
            match verify_compressed(custom_data, evidence_string.trim()).await {
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
