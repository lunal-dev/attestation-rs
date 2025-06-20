use base64;
use flate2::Compression;
use flate2::write::GzEncoder;
use sev_snp::{AttestationReport, SevSnp};
use std::io::Write;

pub fn get_raw_attestation_report() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let sev_snp = SevSnp::new()?;
    let (report, _var_data) = sev_snp.get_attestation_report()?;
    let serialized_report = bincode::serialize(&report)?;
    Ok(serialized_report)
}

pub fn get_parsed_attestation_report() -> Result<AttestationReport, Box<dyn std::error::Error>> {
    let sev_snp = SevSnp::new()?;
    let (report, _var_data) = sev_snp.get_attestation_report()?;
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
