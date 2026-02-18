use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

use sev::firmware::guest::Firmware;
use sev::firmware::host::{CertTableEntry, CertType};

use crate::error::{AttestationError, Result};
use crate::utils::pad_report_data;

use super::evidence::{SnpCertChain, SnpEvidence};

const SEV_PLATFORM_PATH: &str = "/sys/devices/platform/sev-guest";

/// Check if SNP hardware is available on this machine.
pub fn is_available() -> bool {
    std::path::Path::new(SEV_PLATFORM_PATH).exists()
}

/// Extract VCEK/ASK/ARK certificates from the sev crate's cert table entries.
fn certs_to_chain(certs: Vec<CertTableEntry>) -> Option<SnpCertChain> {
    let mut vcek = None;
    let mut ask = None;
    let mut ark = None;

    for entry in &certs {
        let encoded = BASE64.encode(entry.data());
        match entry.cert_type {
            CertType::VCEK | CertType::VLEK => vcek = Some(encoded),
            CertType::ASK => ask = Some(encoded),
            CertType::ARK => ark = Some(encoded),
            _ => {}
        }
    }

    vcek.map(|v| SnpCertChain {
        vcek: v,
        ask,
        ark,
    })
}

/// Generate SNP attestation evidence.
pub async fn generate_evidence(report_data: &[u8]) -> Result<SnpEvidence> {
    let padded = pad_report_data(report_data, 64)?;
    let data: [u8; 64] = padded.try_into().map_err(|_| {
        AttestationError::ReportDataTooLarge { max: 64 }
    })?;

    // Open the /dev/sev-guest device via the sev crate
    let mut firmware = Firmware::open().map_err(|e| {
        AttestationError::HardwareAccessFailed(format!("Firmware::open failed: {}", e))
    })?;

    // Get the extended report (attestation report + certificate table)
    let (report_bytes, certs) = firmware
        .get_ext_report(None, Some(data), Some(0))
        .map_err(|e| {
            AttestationError::HardwareAccessFailed(format!("get_ext_report failed: {}", e))
        })?;

    let cert_chain = certs.and_then(certs_to_chain);

    Ok(SnpEvidence {
        attestation_report: BASE64.encode(&report_bytes),
        cert_chain,
    })
}
