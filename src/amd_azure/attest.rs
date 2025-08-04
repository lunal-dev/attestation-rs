use crate::amd_azure::AttestationEvidence;
use az_snp_vtpm::{imds, vtpm};
use flate2::Compression;
use flate2::write::GzEncoder;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::io::Write;

/// Generate attestation evidence with custom data
pub async fn attest(custom_data: &[u8]) -> Result<AttestationEvidence, Box<dyn Error>> {
    let report = vtpm::get_report()?;
    let quote = vtpm::get_quote(custom_data)?;
    let certs = imds::get_certs().await?;

    Ok(AttestationEvidence {
        report,
        quote,
        certs,
        report_data: custom_data.into(),
    })
}

/// Generate attestation evidence and return as raw bytes
pub async fn attest_bytes(custom_data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let evidence = attest(custom_data).await?;
    evidence.to_bytes()
}

/// Generate attestation evidence, compress with gzip, and encode as base64
pub async fn attest_compressed(custom_data: &[u8]) -> Result<String, Box<dyn Error>> {
    let evidence_bytes = attest_bytes(custom_data).await?;

    // Compress with gzip
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&evidence_bytes)?;
    let compressed = encoder.finish()?;

    // Encode as base64
    Ok(base64::encode(compressed))
}
