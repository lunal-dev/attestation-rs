use crate::error::{AttestationError, Result};
use crate::utils::pad_report_data;

use super::evidence::SnpEvidence;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use std::path::Path;

const SEV_GUEST_PATH: &str = "/dev/sev-guest";
const SEV_PLATFORM_PATH: &str = "/sys/devices/platform/sev-guest";

/// Check if SNP hardware is available on this machine.
pub fn is_available() -> bool {
    Path::new(SEV_PLATFORM_PATH).exists()
}

/// Generate SNP attestation evidence.
pub async fn generate_evidence(report_data: &[u8]) -> Result<SnpEvidence> {
    let padded = pad_report_data(report_data, 64)?;

    // Use /dev/sev-guest to get extended report
    // The extended report includes the attestation report + cert table
    let (report_bytes, cert_table) = get_extended_report(&padded)?;

    let attestation_report = BASE64.encode(&report_bytes);

    // Parse cert table if available
    let cert_chain = if !cert_table.is_empty() {
        parse_cert_table(&cert_table)
    } else {
        None
    };

    Ok(SnpEvidence {
        attestation_report,
        cert_chain,
    })
}

/// Get extended attestation report via /dev/sev-guest ioctl.
fn get_extended_report(report_data: &[u8; 64]) -> Result<(Vec<u8>, Vec<u8>)> {
    use std::fs::OpenOptions;
    use std::os::unix::io::AsRawFd;

    let _dev = OpenOptions::new()
        .read(true)
        .write(true)
        .open(SEV_GUEST_PATH)
        .map_err(|e| {
            AttestationError::HardwareAccessFailed(format!("open {}: {}", SEV_GUEST_PATH, e))
        })?;

    // SNP_GET_EXT_REPORT ioctl
    // For now, use a simplified approach - in production this would use
    // the sev crate's Firmware::open() and get_ext_report()

    // The ioctl number for SNP_GET_EXT_REPORT
    const SNP_GET_EXT_REPORT: u64 = 0xC0185302;

    #[repr(C)]
    struct SnpGuestRequestIoctl {
        msg_version: u8,
        req_data: u64,
        resp_data: u64,
        fw_err: u64,
    }

    #[repr(C)]
    struct SnpExtReportReq {
        data: SnpReportReq,
        certs_address: u64,
        certs_len: u32,
    }

    #[repr(C)]
    struct SnpReportReq {
        report_data: [u8; 64],
        vmpl: u32,
        reserved: [u8; 28],
    }

    // First call with certs_len = 0 to get the required buffer size
    let mut req = SnpReportReq {
        report_data: [0u8; 64],
        vmpl: 0,
        reserved: [0u8; 28],
    };
    req.report_data.copy_from_slice(report_data);

    // Allocate a buffer for the response (report + certs)
    let mut report_buf = vec![0u8; 4096];
    let mut cert_buf = vec![0u8; 4096 * 4]; // Usually enough for cert table

    let mut ext_req = SnpExtReportReq {
        data: req,
        certs_address: cert_buf.as_mut_ptr() as u64,
        certs_len: cert_buf.len() as u32,
    };

    let mut ioctl_req = SnpGuestRequestIoctl {
        msg_version: 1,
        req_data: &mut ext_req as *mut _ as u64,
        resp_data: report_buf.as_mut_ptr() as u64,
        fw_err: 0,
    };

    let ret = unsafe {
        libc::ioctl(
            _dev.as_raw_fd(),
            SNP_GET_EXT_REPORT,
            &mut ioctl_req as *mut _,
        )
    };

    if ret != 0 {
        return Err(AttestationError::HardwareAccessFailed(format!(
            "SNP_GET_EXT_REPORT ioctl failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    // The report is in report_buf (first 1184 bytes)
    let report = report_buf[..1184].to_vec();
    let certs = cert_buf[..ext_req.certs_len as usize].to_vec();

    Ok((report, certs))
}

/// Parse the certificate table from extended report.
fn parse_cert_table(data: &[u8]) -> Option<super::evidence::SnpCertChain> {
    // The cert table format is a series of (guid, offset, length) entries
    // followed by the certificate data.
    // GUID types:
    //   VCEK: 63da758d-e664-4564-adc5-f4b93be8accd
    //   ASK:  4ab7b379-bbac-4fe4-a02f-05aef327c782
    //   ARK:  c0b406a4-a803-4952-9743-3fb6014cd0ae

    if data.len() < 24 {
        return None;
    }

    // Each entry is: 16 bytes GUID + 4 bytes offset + 4 bytes length = 24 bytes
    let mut vcek = None;
    let mut ask = None;
    let mut ark = None;

    let mut pos = 0;
    while pos + 24 <= data.len() {
        let guid = &data[pos..pos + 16];
        let offset = u32::from_le_bytes(data[pos + 16..pos + 20].try_into().ok()?) as usize;
        let length = u32::from_le_bytes(data[pos + 20..pos + 24].try_into().ok()?) as usize;

        // Check for null GUID (end of table)
        if guid.iter().all(|&b| b == 0) {
            break;
        }

        if offset + length <= data.len() {
            let cert_data = data[offset..offset + length].to_vec();
            let cert_b64 = BASE64.encode(&cert_data);

            // Match GUIDs
            let guid_hex = hex::encode(guid);
            match guid_hex.as_str() {
                "63da758de6644564adc5f4b93be8accd" => vcek = Some(cert_b64),
                "4ab7b379bbac4fe4a02f05aef327c782" => ask = Some(cert_b64),
                "c0b406a4a80349529743fb6014cd0ae" => ark = Some(cert_b64),
                _ => {} // Unknown GUID, skip
            }
        }

        pos += 24;
    }

    vcek.map(|v| super::evidence::SnpCertChain {
        vcek: v,
        ask,
        ark,
    })
}
