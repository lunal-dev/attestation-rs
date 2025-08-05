use base64;
use dcap_rs::types::quotes::version_4::QuoteV4;
use flate2::Compression;
use flate2::write::GzEncoder;
use std::io::Write;
use tdx::Tdx;

pub fn get_raw_attestation_report() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let tdx = Tdx::new();
    let (raw_report, _) = tdx.get_attestation_report_raw()?;
    Ok(raw_report)
}

pub fn get_parsed_attestation_report() -> Result<QuoteV4, Box<dyn std::error::Error>> {
    let raw_report = get_raw_attestation_report()?;
    let report = QuoteV4::from_bytes(&raw_report);
    Ok(report)
}

pub fn get_compressed_encoded_attestation() -> Result<String, Box<dyn std::error::Error>> {
    let raw_report = get_raw_attestation_report()?;
    let compressed_report = compress_gzip(&raw_report)?;
    let encoded_report = base64::encode(&compressed_report);
    Ok(encoded_report)
}

fn compress_gzip(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    let compressed = encoder.finish()?;
    Ok(compressed)
}
