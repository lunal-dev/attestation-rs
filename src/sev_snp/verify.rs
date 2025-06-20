use base64;
use flate2::read::GzDecoder;
use sev_snp::{AttestationFlow, SevSnp};
use std::io::Read;

#[derive(Debug)]
pub enum VerificationError {
    ParseError(String),
    DecompressionError(String),
    VerificationError(String),
    SevSnpError(String),
}

impl From<sev_snp::error::SevSnpError> for VerificationError {
    fn from(err: sev_snp::error::SevSnpError) -> Self {
        VerificationError::SevSnpError(format!("{}", err))
    }
}

#[derive(Debug)]
pub struct VerifiedOutput {
    pub report: sev_snp::AttestationReport,
    pub verified: bool,
}

/// Verify attestation from HTTP header string
pub async fn verify_attestation(
    attestation_header: &str,
) -> Result<VerifiedOutput, VerificationError> {
    // Parse and decode the attestation
    let report = parse_attestation_header(attestation_header)?;

    // Perform verification
    verify_attestation_report(report).await
}

/// Parse attestation from header string (assumes base64 + gzip format)
fn parse_attestation_header(
    attestation_header: &str,
) -> Result<sev_snp::AttestationReport, VerificationError> {
    let trimmed = attestation_header.trim();

    // Decode base64
    let compressed_bytes = base64::decode(trimmed)
        .map_err(|e| VerificationError::ParseError(format!("Base64 decode failed: {}", e)))?;

    // Decompress gzip
    let mut decoder = GzDecoder::new(&compressed_bytes[..]);
    let mut report_bytes = Vec::new();
    decoder.read_to_end(&mut report_bytes).map_err(|e| {
        VerificationError::DecompressionError(format!("Gzip decompression failed: {}", e))
    })?;

    // Deserialize the attestation report
    let report: sev_snp::AttestationReport = bincode::deserialize(&report_bytes).map_err(|e| {
        VerificationError::ParseError(format!("Failed to deserialize attestation report: {}", e))
    })?;

    Ok(report)
}

/// Verify the attestation report using SEV-SNP library
async fn verify_attestation_report(
    report: sev_snp::AttestationReport,
) -> Result<VerifiedOutput, VerificationError> {
    let sev_snp = SevSnp::new().map_err(|e| {
        VerificationError::SevSnpError(format!("Failed to initialize SevSnp: {}", e))
    })?;

    // Try verification with default options first (Regular flow)
    match sev_snp.verify_attestation_report(&report, None) {
        Ok(_) => Ok(VerifiedOutput {
            report,
            verified: true,
        }),
        Err(e) => {
            // If regular verification fails, you might want to try extended verification
            // Note: Extended verification only works on the same SEV-SNP VM where the report was generated
            match sev_snp.verify_attestation_report_with_options(
                &report,
                &AttestationFlow::Extended,
                None,
            ) {
                Ok(_) => Ok(VerifiedOutput {
                    report,
                    verified: true,
                }),
                Err(extended_err) => Err(VerificationError::VerificationError(format!(
                    "Both regular and extended verification failed. Regular: {}, Extended: {}",
                    e, extended_err
                ))),
            }
        }
    }
}
