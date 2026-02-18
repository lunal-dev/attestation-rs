use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL, Engine};

use az_tdx_vtpm::{hcl, imds, is_tdx_cvm, tdx, vtpm};

use crate::error::{AttestationError, Result};
use crate::platforms::tpm_common::TpmQuote;
use crate::utils::pad_report_data;

use super::evidence::AzTdxEvidence;

/// Check if Azure TDX platform is available.
pub fn is_available() -> bool {
    match is_tdx_cvm() {
        Ok(is_tdx) => is_tdx,
        Err(e) => {
            log::debug!("Azure TDX detection failed: {}", e);
            false
        }
    }
}

/// Convert az-cvm-vtpm Quote to our TpmQuote format.
fn quote_to_tpm_quote(q: vtpm::Quote) -> TpmQuote {
    TpmQuote {
        signature: hex::encode(q.signature()),
        message: hex::encode(q.message()),
        pcrs: q.pcrs_sha256().map(hex::encode).collect(),
    }
}

/// Generate Azure TDX attestation evidence.
pub async fn generate_evidence(report_data: &[u8]) -> Result<AzTdxEvidence> {
    let _padded = pad_report_data(report_data, 64)?;

    // 1. Read HCL report from vTPM NVRAM (extends PCR with report_data hash)
    let hcl_report_bytes = vtpm::get_report().map_err(|e| {
        AttestationError::HardwareAccessFailed(format!("vtpm::get_report failed: {}", e))
    })?;

    // 2. Parse HCL envelope and extract TD report
    let hcl_report = hcl::HclReport::new(hcl_report_bytes.clone()).map_err(|e| {
        AttestationError::HardwareAccessFailed(format!("HclReport::new failed: {}", e))
    })?;
    let td_report: tdx::TdReport = hcl_report.try_into().map_err(|e: hcl::HclError| {
        AttestationError::HardwareAccessFailed(format!(
            "failed to extract TdReport from HCL: {}",
            e
        ))
    })?;

    // 3. Get TD quote from Azure IMDS (signed by Intel QE)
    let td_quote_bytes = imds::get_td_quote(&td_report).map_err(|e| {
        AttestationError::HardwareAccessFailed(format!("imds::get_td_quote failed: {}", e))
    })?;

    // 4. Generate TPM quote with report_data as nonce
    let quote = vtpm::get_quote(report_data).map_err(|e| {
        AttestationError::HardwareAccessFailed(format!("vtpm::get_quote failed: {}", e))
    })?;
    let tpm_quote = quote_to_tpm_quote(quote);

    // 5. Assemble evidence
    Ok(AzTdxEvidence {
        version: 1,
        tpm_quote,
        hcl_report: BASE64URL.encode(&hcl_report_bytes),
        td_quote: BASE64URL.encode(&td_quote_bytes),
    })
}
