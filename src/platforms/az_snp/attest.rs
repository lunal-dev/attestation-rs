use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL, Engine};
use serde::Deserialize;

use az_cvm_vtpm::vtpm;

use crate::error::{AttestationError, Result};
use crate::platforms::tpm_common::TpmQuote;
use crate::utils::pad_report_data;

use super::evidence::AzSnpEvidence;

const IMDS_CERT_URL: &str = "http://169.254.169.254/metadata/THIM/amd/certification";
const TPMRM_PATH: &str = "/dev/tpmrm0";
const TPM_PATH: &str = "/dev/tpm0";
const DMI_SYS_VENDOR_PATH: &str = "/sys/class/dmi/id/sys_vendor";
const DMI_BOARD_VENDOR_PATH: &str = "/sys/class/dmi/id/board_vendor";

#[derive(Deserialize)]
struct ImdsCertificates {
    #[serde(rename = "vcekCert")]
    vcek: String,
}

/// Check if Azure SNP platform is available.
pub fn is_available() -> bool {
    crate::platforms::snp::attest::is_available() && has_tpm_device() && is_azure_vm()
}

fn has_tpm_device() -> bool {
    std::path::Path::new(TPMRM_PATH).exists() || std::path::Path::new(TPM_PATH).exists()
}

fn is_azure_vm() -> bool {
    [DMI_SYS_VENDOR_PATH, DMI_BOARD_VENDOR_PATH]
        .into_iter()
        .any(|path| match std::fs::read_to_string(path) {
            Ok(value) => value.trim() == "Microsoft Corporation",
            Err(e) => {
                log::debug!("Azure SNP detection: failed to read {path}: {e}");
                false
            }
        })
}

/// Convert a PEM-encoded certificate to DER bytes.
fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let (_label, der) = pem_rfc7468::decode_vec(pem.as_bytes()).map_err(|e| {
        AttestationError::CertFetchError(format!("failed to decode VCEK PEM: {}", e))
    })?;
    Ok(der)
}

/// Convert az-cvm-vtpm Quote to our TpmQuote format.
fn quote_to_tpm_quote(q: vtpm::Quote) -> TpmQuote {
    TpmQuote {
        signature: hex::encode(q.signature()),
        message: hex::encode(q.message()),
        pcrs: q.pcrs_sha256().map(hex::encode).collect(),
    }
}

/// Generate Azure SNP attestation evidence.
pub async fn generate_evidence(report_data: &[u8]) -> Result<AzSnpEvidence> {
    // Validate size fits in 64-byte report_data field, but do NOT pad:
    // TPM2B_DATA (used by vtpm::get_quote) has a smaller max size than 64 bytes
    // on Azure vTPMs, so we must pass the original unpadded data as the nonce.
    let _ = pad_report_data(report_data, 64)?;

    // 1. Read HCL report from vTPM NVRAM
    let hcl_report_bytes = vtpm::get_report().map_err(|e| {
        AttestationError::HardwareAccessFailed(format!("vtpm::get_report failed: {}", e))
    })?;

    // 2. Generate TPM quote with report_data as nonce (unpadded)
    let quote = vtpm::get_quote(report_data).map_err(|e| {
        AttestationError::HardwareAccessFailed(format!("vtpm::get_quote failed: {}", e))
    })?;
    let tpm_quote = quote_to_tpm_quote(quote);

    // 3. Fetch VCEK certificate from Azure IMDS
    let certs: ImdsCertificates = reqwest::Client::new()
        .get(IMDS_CERT_URL)
        .header("Metadata", "true")
        .send()
        .await
        .map_err(|e| AttestationError::CertFetchError(format!("IMDS request failed: {}", e)))?
        .error_for_status()
        .map_err(|e| AttestationError::CertFetchError(format!("IMDS returned error: {}", e)))?
        .json()
        .await
        .map_err(|e| {
            AttestationError::CertFetchError(format!("failed to parse IMDS cert response: {}", e))
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
