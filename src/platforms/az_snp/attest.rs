use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL, Engine};
use std::process::Command;

use crate::error::{AttestationError, Result};
use crate::platforms::tpm_common::TpmQuote;
use crate::utils::pad_report_data;

use super::evidence::AzSnpEvidence;

/// Default TPM device paths to try.
const TPM_DEVICE_PATHS: &[&str] = &["/dev/tpmrm0", "/dev/tpm0"];

/// NV index where the HCL report is stored by Azure vTPM.
const HCL_REPORT_NV_INDEX: &str = "0x01400001";

/// Persistent handle for the Attestation Key (AK).
const AK_HANDLE: &str = "0x81000003";

/// Azure IMDS endpoint for AMD certification (VCEK + cert chain).
const IMDS_THIM_ENDPOINT: &str =
    "http://169.254.169.254/metadata/THIM/amd/certification";

/// Check if Azure SNP platform is available.
pub fn is_available() -> bool {
    // Azure SNP CVMs have: a TPM device, Azure IMDS, and HCL report in NV
    has_tpm_device() && is_azure_environment()
}

fn has_tpm_device() -> bool {
    TPM_DEVICE_PATHS.iter().any(|p| std::path::Path::new(p).exists())
}

fn is_azure_environment() -> bool {
    // Check for Hyper-V KVP pool or IMDS indicator
    std::path::Path::new("/var/lib/hyperv/.kvp_pool_3").exists()
        || std::path::Path::new("/var/lib/waagent").exists()
        || std::env::var("AZURE_INSTANCE_METADATA_SERVICE").is_ok()
}

fn find_tpm_device() -> Result<&'static str> {
    // Check env var first (allows override for testing)
    if let Ok(dev) = std::env::var("ATTESTATION_TPM_DEVICE") {
        if std::path::Path::new(&dev).exists() {
            // We can't return a &'static str from an env var, so just
            // check if the default paths work
            log::debug!("ATTESTATION_TPM_DEVICE={}, checking default paths", dev);
        }
    }
    TPM_DEVICE_PATHS
        .iter()
        .find(|p| std::path::Path::new(p).exists())
        .copied()
        .ok_or_else(|| {
            AttestationError::HardwareAccessFailed("no TPM device found".to_string())
        })
}

/// Read the HCL report from TPM NVRAM using tpm2_nvread.
fn read_hcl_report() -> Result<Vec<u8>> {
    let output = Command::new("tpm2_nvread")
        .args([HCL_REPORT_NV_INDEX, "-C", "o"])
        .output()
        .map_err(|e| {
            AttestationError::HardwareAccessFailed(format!(
                "failed to execute tpm2_nvread: {} (is tpm2-tools installed?)",
                e
            ))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AttestationError::HardwareAccessFailed(format!(
            "tpm2_nvread failed: {}",
            stderr.trim()
        )));
    }

    if output.stdout.is_empty() {
        return Err(AttestationError::HardwareAccessFailed(
            "tpm2_nvread returned empty data".to_string(),
        ));
    }

    Ok(output.stdout)
}

/// Generate a TPM quote using tpm2_quote with all 24 PCRs.
fn generate_tpm_quote(report_data: &[u8]) -> Result<TpmQuote> {
    let _tpm_dev = find_tpm_device()?;

    // Write nonce to a temp file
    let nonce_file = tempfile::NamedTempFile::new().map_err(|e| {
        AttestationError::HardwareAccessFailed(format!("failed to create temp file: {}", e))
    })?;
    std::fs::write(nonce_file.path(), report_data).map_err(|e| {
        AttestationError::HardwareAccessFailed(format!("failed to write nonce: {}", e))
    })?;

    let msg_file = tempfile::NamedTempFile::new().map_err(|e| {
        AttestationError::HardwareAccessFailed(format!("failed to create temp file: {}", e))
    })?;
    let sig_file = tempfile::NamedTempFile::new().map_err(|e| {
        AttestationError::HardwareAccessFailed(format!("failed to create temp file: {}", e))
    })?;

    // Run tpm2_quote
    let pcr_list = "sha256:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23";
    let output = Command::new("tpm2_quote")
        .args([
            "-c",
            AK_HANDLE,
            "-l",
            pcr_list,
            "-q",
            &nonce_file.path().to_string_lossy(),
            "-m",
            &msg_file.path().to_string_lossy(),
            "-s",
            &sig_file.path().to_string_lossy(),
        ])
        .output()
        .map_err(|e| {
            AttestationError::HardwareAccessFailed(format!(
                "failed to execute tpm2_quote: {} (is tpm2-tools installed?)",
                e
            ))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AttestationError::HardwareAccessFailed(format!(
            "tpm2_quote failed: {}",
            stderr.trim()
        )));
    }

    // Read binary outputs
    let sig_bytes = std::fs::read(sig_file.path()).map_err(|e| {
        AttestationError::HardwareAccessFailed(format!("failed to read sig file: {}", e))
    })?;
    let msg_bytes = std::fs::read(msg_file.path()).map_err(|e| {
        AttestationError::HardwareAccessFailed(format!("failed to read msg file: {}", e))
    })?;

    // Parse PCR values using tpm2_pcrread for clean hex output
    let pcrs = read_pcr_values()?;

    // The signature from tpm2_quote -F tss is in TPMT_SIGNATURE format
    // We need to extract the raw RSA signature bytes
    let raw_sig = extract_rsassa_signature(&sig_bytes)?;

    Ok(TpmQuote {
        signature: hex::encode(raw_sig),
        message: hex::encode(msg_bytes),
        pcrs,
    })
}

/// Read all 24 PCR values as hex strings.
fn read_pcr_values() -> Result<Vec<String>> {
    let output = Command::new("tpm2_pcrread")
        .args(["sha256:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23"])
        .output()
        .map_err(|e| {
            AttestationError::HardwareAccessFailed(format!(
                "failed to execute tpm2_pcrread: {}",
                e
            ))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AttestationError::HardwareAccessFailed(format!(
            "tpm2_pcrread failed: {}",
            stderr.trim()
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut pcrs = Vec::with_capacity(24);

    // Parse output format: "  N : 0xHEXHEXHEX..."
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(hex_part) = line.split("0x").nth(1) {
            let hex_str = hex_part.trim().to_lowercase();
            if hex_str.len() == 64 {
                // 32 bytes = 64 hex chars
                pcrs.push(hex_str);
            }
        }
    }

    if pcrs.len() != 24 {
        return Err(AttestationError::HardwareAccessFailed(format!(
            "expected 24 PCR values, got {}",
            pcrs.len()
        )));
    }

    Ok(pcrs)
}

/// Extract raw RSA signature from TPMT_SIGNATURE structure.
/// Format: sigAlg (2 bytes BE) + hashAlg (2 bytes BE) + size (2 bytes BE) + sig data
fn extract_rsassa_signature(tpmt_sig: &[u8]) -> Result<Vec<u8>> {
    if tpmt_sig.len() < 6 {
        return Err(AttestationError::HardwareAccessFailed(
            "TPMT_SIGNATURE too short".to_string(),
        ));
    }

    let sig_alg = u16::from_be_bytes([tpmt_sig[0], tpmt_sig[1]]);
    // TPM_ALG_RSASSA = 0x0014
    if sig_alg != 0x0014 {
        return Err(AttestationError::HardwareAccessFailed(format!(
            "unexpected signature algorithm: 0x{:04x} (expected RSASSA 0x0014)",
            sig_alg
        )));
    }

    // hashAlg at offset 2, then size at offset 4
    let sig_size = u16::from_be_bytes([tpmt_sig[4], tpmt_sig[5]]) as usize;
    if tpmt_sig.len() < 6 + sig_size {
        return Err(AttestationError::HardwareAccessFailed(format!(
            "TPMT_SIGNATURE truncated: need {} bytes, have {}",
            6 + sig_size,
            tpmt_sig.len()
        )));
    }

    Ok(tpmt_sig[6..6 + sig_size].to_vec())
}

/// Fetch VCEK certificate from Azure IMDS THIM endpoint.
fn fetch_vcek_from_imds() -> Result<Vec<u8>> {
    // Use a blocking HTTP request (we're in async context but IMDS is local)
    let output = Command::new("curl")
        .args([
            "-s",
            "-H",
            "Metadata:true",
            IMDS_THIM_ENDPOINT,
        ])
        .output()
        .map_err(|e| {
            AttestationError::CertFetchError(format!("failed to call IMDS: {}", e))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AttestationError::CertFetchError(format!(
            "IMDS request failed: {}",
            stderr.trim()
        )));
    }

    // Parse JSON response to extract vcekCert
    let response: serde_json::Value =
        serde_json::from_slice(&output.stdout).map_err(|e| {
            AttestationError::CertFetchError(format!("failed to parse IMDS response: {}", e))
        })?;

    let vcek_pem = response["vcekCert"]
        .as_str()
        .ok_or_else(|| {
            AttestationError::CertFetchError("IMDS response missing vcekCert field".to_string())
        })?;

    // Convert PEM to DER
    pem_to_der(vcek_pem)
}

/// Convert a PEM-encoded certificate to DER bytes.
fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let pem_clean: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");

    base64::engine::general_purpose::STANDARD
        .decode(pem_clean.trim())
        .map_err(|e| {
            AttestationError::CertFetchError(format!("failed to decode PEM base64: {}", e))
        })
}

/// Generate Azure SNP attestation evidence.
pub async fn generate_evidence(report_data: &[u8]) -> Result<AzSnpEvidence> {
    let _padded = pad_report_data(report_data, 64)?;

    // 1. Read HCL report from TPM NVRAM
    let hcl_report_bytes = read_hcl_report()?;

    // 2. Generate TPM quote with the report data as nonce.
    // Azure vTPMs limit qualifying data to ~50 bytes. The raw report_data
    // (before padding) is used as the TPM nonce.
    let tpm_quote = generate_tpm_quote(report_data)?;

    // 3. Fetch VCEK certificate from Azure IMDS
    let vcek_der = fetch_vcek_from_imds()?;

    // 4. Assemble evidence
    Ok(AzSnpEvidence {
        version: 1,
        tpm_quote,
        hcl_report: BASE64URL.encode(&hcl_report_bytes),
        vcek: BASE64URL.encode(&vcek_der),
    })
}
