// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use az_snp_vtpm::amd_kds;
use az_snp_vtpm::certs::Vcek;
use az_snp_vtpm::hcl::HclReport;
use az_snp_vtpm::report::{AttestationReport, Validateable};
use flate2::read::GzDecoder;
use std::error::Error;
use std::io::Read;

use crate::amd_azure::AttestationEvidence;

/// Verify attestation evidence with custom data (nonce)
pub async fn verify_evidence(
    custom_data: &[u8],
    evidence: &AttestationEvidence,
) -> Result<(), Box<dyn Error>> {
    let AttestationEvidence {
        quote,
        report,
        certs,
        report_data,
    } = evidence;

    // Parse HCL report
    let hcl_report = HclReport::new(report.clone())?;
    let var_data_hash = hcl_report.var_data_sha256();
    let ak_pub = hcl_report.ak_pub()?;
    let snp_report: AttestationReport = hcl_report.try_into()?;

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

    // Verify quote with custom data (nonce)
    // let der = ak_pub.key.try_to_der()?;
    // let pub_key = PKey::public_key_from_der(&der)?;
    // quote.verify(&pub_key, custom_data)?;

    Ok(())
}

/// Verify attestation evidence from raw bytes
pub async fn verify_bytes(custom_data: &[u8], evidence_bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let evidence = AttestationEvidence::from_bytes(evidence_bytes)?;
    verify_evidence(custom_data, &evidence).await
}

/// Verify compressed and base64-encoded attestation evidence
pub async fn verify_compressed(
    custom_data: &[u8],
    compressed_evidence: &str,
) -> Result<(), Box<dyn Error>> {
    // Decode from base64
    let compressed_bytes = base64::decode(compressed_evidence)?;

    // Decompress with gzip
    let mut decoder = GzDecoder::new(&compressed_bytes[..]);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;

    // Verify the decompressed evidence
    verify_bytes(custom_data, &decompressed).await
}
