use std::env;
use std::fs;

#[cfg(feature = "attestation")]
use lunal_attestation::amd::attest;
use lunal_attestation::amd::verify::verify_compressed;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!(
            "Usage: {} <attest|verify> [evidence_file] [custom_data] [--check-custom-data]",
            args[0]
        );
        eprintln!("  attest [custom_data]: Generate attestation evidence");
        eprintln!("  verify <file> [custom_data] [--check-custom-data]: Verify evidence from file");
        eprintln!("    --check-custom-data: Enable custom data validation (default: false)");
        return Ok(());
    }

    // Check for --check-custom-data flag
    let check_custom_data = args.iter().any(|arg| arg == "--check-custom-data");

    // Get custom data from args or use empty (excluding flags)
    let custom_data = if args.len() > 3 && !args[3].starts_with("--") {
        args[3].as_bytes()
    } else if args.len() > 2 && args[1] == "attest" && !args[2].starts_with("--") {
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

            // Read evidence from file (assuming base64 compressed format)
            let evidence_string = fs::read_to_string(&args[2])?;

            // Verify the evidence
            match verify_compressed(custom_data, evidence_string.trim(), Some(check_custom_data))
                .await
            {
                Ok(verification_result) => {
                    // Create a single JSON object with all verification results
                    let json_output = serde_json::json!({
                        "status": "verified",
                        "report": verification_result.report,
                        "certs": verification_result.certs,
                        "report_data": verification_result.report_data
                    });

                    println!("{}", serde_json::to_string_pretty(&json_output)?);
                }
                Err(e) => {
                    let error_json = serde_json::json!({
                        "status": "failed",
                        "error": e.to_string()
                    });
                    println!("{}", serde_json::to_string_pretty(&error_json)?);
                }
            }
        }

        _ => {
            eprintln!("Unknown command: {}", args[1]);
            eprintln!("Use 'attest' or 'verify'");
        }
    }

    Ok(())
}
