// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use amd_vtpm::amd_kds;
use amd_vtpm::certs::Vcek;
use amd_vtpm::hcl::HclReport;
use amd_vtpm::report::{AttestationReport, Validateable};
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::io::Read;

use crate::amd_azure::AttestationEvidence;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub report: serde_json::Value,
    pub certs: serde_json::Value,
    pub report_data: String,
}

/// Verify attestation evidence with custom data (nonce)
pub async fn verify_evidence(
    custom_data: &[u8],
    evidence: &AttestationEvidence,
    check_custom_data: Option<bool>,
) -> Result<VerificationResult, Box<dyn Error>> {
    let AttestationEvidence {
        report,
        certs,
        report_data,
    } = evidence.clone();

    // Convert fields to JSON
    let certs_json = serde_json::to_value(&certs)?;
    let report_data_string = String::from_utf8_lossy(&report_data).to_string();

    // Parse HCL report
    let hcl_report = HclReport::new(report.clone())?;

    let var_data_hash = hcl_report.var_data_sha256();
    // let ak_pub = hcl_report.ak_pub()?;
    let snp_report: AttestationReport = hcl_report.try_into()?;
    let report_json = serde_json::to_value(&snp_report)?;

    // Get and validate certificate chain
    let cert_chain = amd_kds::get_cert_chain().await?;
    let vcek = Vcek::from_pem(&certs.vcek)?;

    // Validate certificates and report
    cert_chain.validate()?;
    vcek.validate(&cert_chain)?;
    snp_report.validate(&vcek)?;

    // Verify var_data_hash matches report_data
    if var_data_hash != snp_report.report_data[..32] {
        return Err("Variable data hash mismatch".into());
    }

    if check_custom_data.unwrap_or(false) {
        let data_vec: Vec<u8> = custom_data.into();
        if data_vec != report_data {
            return Err("Variable data hash mismatch".into());
        }
    }

    // Return the converted fields as a struct
    Ok(VerificationResult {
        report: report_json,
        certs: certs_json,
        report_data: report_data_string,
    })
}
/// Verify attestation evidence from raw bytes
pub async fn verify_bytes(
    custom_data: &[u8],
    evidence_bytes: &[u8],
    check_custom_data: Option<bool>,
) -> Result<VerificationResult, Box<dyn Error>> {
    let evidence = AttestationEvidence::from_bytes(evidence_bytes)?;
    verify_evidence(custom_data, &evidence, check_custom_data).await
}

/// Verify compressed and base64-encoded attestation evidence
pub async fn verify_compressed(
    custom_data: &[u8],
    compressed_evidence: &str,
    check_custom_data: Option<bool>,
) -> Result<VerificationResult, Box<dyn Error>> {
    // Decode from base64
    let compressed_bytes = base64::decode(compressed_evidence)?;

    // Decompress with gzip
    let mut decoder = GzDecoder::new(&compressed_bytes[..]);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;

    // Verify the decompressed evidence
    verify_bytes(custom_data, &decompressed, check_custom_data).await
}
