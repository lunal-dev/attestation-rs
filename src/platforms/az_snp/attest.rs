use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL, Engine};

use az_snp_vtpm::{imds, is_snp_cvm, vtpm};

use crate::error::{AttestationError, Result};
use crate::platforms::tpm_common::TpmQuote;
use crate::utils::pad_report_data;

use super::evidence::AzSnpEvidence;

/// Check if Azure SNP platform is available.
pub fn is_available() -> bool {
    match is_snp_cvm() {
        Ok(is_snp) => is_snp,
        Err(e) => {
            log::warn!("Azure SNP detection failed: {}", e);
            false
        }
    }
}

/// Convert a PEM-encoded certificate to DER bytes.
fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let (_label, der) = pem_rfc7468::decode_vec(pem.as_bytes()).map_err(|e| {
        AttestationError::CertFetchError(format!("failed to decode VCEK PEM: {}", e))
    })?;
    Ok(der)
}

/// Convert az-snp-vtpm Quote to our TpmQuote format.
fn quote_to_tpm_quote(q: vtpm::Quote) -> TpmQuote {
    TpmQuote {
        signature: hex::encode(q.signature()),
        message: hex::encode(q.message()),
        pcrs: q.pcrs_sha256().map(hex::encode).collect(),
    }
}

/// Generate Azure SNP attestation evidence.
pub async fn generate_evidence(report_data: &[u8]) -> Result<AzSnpEvidence> {
    let padded = pad_report_data(report_data, 64)?;

    // 1. Read HCL report from vTPM NVRAM
    let hcl_report_bytes = vtpm::get_report().map_err(|e| {
        AttestationError::HardwareAccessFailed(format!("vtpm::get_report failed: {}", e))
    })?;

    // 2. Generate TPM quote with report_data as nonce
    let quote = vtpm::get_quote(&padded).map_err(|e| {
        AttestationError::HardwareAccessFailed(format!("vtpm::get_quote failed: {}", e))
    })?;
    let tpm_quote = quote_to_tpm_quote(quote);

    // 3. Fetch VCEK certificate from Azure IMDS
    let certs = imds::get_certs().map_err(|e| {
        AttestationError::CertFetchError(format!("imds::get_certs failed: {}", e))
    })?;
    let vcek_der = pem_to_der(&certs.vcek)?;

    // 4. Assemble evidence
    Ok(AzSnpEvidence {
        version: 1,
        tpm_quote,
        hcl_report: BASE64URL.encode(&hcl_report_bytes),
        vcek: BASE64URL.encode(&vcek_der),
    })
}
