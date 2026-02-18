use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use std::path::Path;

use crate::error::{AttestationError, Result};
use crate::utils::pad_report_data;

use super::evidence::TdxEvidence;

const TSM_REPORT_PATH: &str = "/sys/kernel/config/tsm/report";
const TDX_GUEST_DEV: &str = "/dev/tdx_guest";
const CCEL_DATA_PATH: &str = "/sys/firmware/acpi/tables/data/CCEL";

/// Check if TDX hardware is available.
pub fn is_available() -> bool {
    // Check ConfigFS TSM with tdx_guest provider, or /dev/tdx_guest
    check_tsm_provider() || Path::new(TDX_GUEST_DEV).exists()
}

fn check_tsm_provider() -> bool {
    if !Path::new(TSM_REPORT_PATH).exists() {
        return false;
    }
    // Try to create a temp dir and check provider
    if let Ok(entries) = std::fs::read_dir(TSM_REPORT_PATH) {
        // If path exists but we can create entries, the TSM subsystem is available
        let _ = entries;
        return true;
    }
    false
}

/// Generate TDX attestation evidence.
pub async fn generate_evidence(report_data: &[u8]) -> Result<TdxEvidence> {
    let padded = pad_report_data(report_data, 64)?;

    // Try ConfigFS TSM first, fall back to ioctl
    let quote_bytes = match generate_quote_tsm(&padded) {
        Ok(q) => q,
        Err(_) => generate_quote_ioctl(&padded)?,
    };

    let quote = BASE64.encode(&quote_bytes);

    // Read CC eventlog if available
    let cc_eventlog = read_eventlog().ok().flatten();

    Ok(TdxEvidence { quote, cc_eventlog })
}

/// Generate quote via Linux ConfigFS TSM reports.
fn generate_quote_tsm(report_data: &[u8; 64]) -> Result<Vec<u8>> {
    use std::fs;

    let tsm_path = Path::new(TSM_REPORT_PATH);
    if !tsm_path.exists() {
        return Err(AttestationError::HardwareAccessFailed(
            "ConfigFS TSM not available".to_string(),
        ));
    }

    // Create temporary directory under TSM report path
    let temp_dir = tempfile::tempdir_in(tsm_path).map_err(|e| {
        AttestationError::HardwareAccessFailed(format!("create TSM report dir: {}", e))
    })?;

    let report_path = temp_dir.path();

    // Check provider is tdx_guest
    let provider = fs::read_to_string(report_path.join("provider")).map_err(|e| {
        AttestationError::HardwareAccessFailed(format!("read TSM provider: {}", e))
    })?;

    if !provider.trim().contains("tdx_guest") {
        // Clean up and leave the temp dir (will be cleaned by Drop)
        return Err(AttestationError::HardwareAccessFailed(format!(
            "TSM provider is '{}', not tdx_guest",
            provider.trim()
        )));
    }

    // Write report_data to inblob
    fs::write(report_path.join("inblob"), report_data).map_err(|e| {
        AttestationError::HardwareAccessFailed(format!("write inblob: {}", e))
    })?;

    // Read quote from outblob
    let quote = fs::read(report_path.join("outblob")).map_err(|e| {
        AttestationError::HardwareAccessFailed(format!("read outblob: {}", e))
    })?;

    // Check generation counter for race detection
    let gen_str = fs::read_to_string(report_path.join("generation")).map_err(|e| {
        AttestationError::HardwareAccessFailed(format!("read generation: {}", e))
    })?;

    let generation: u32 = gen_str.trim().parse().map_err(|e| {
        AttestationError::HardwareAccessFailed(format!("parse generation: {}", e))
    })?;

    if generation > 1 {
        return Err(AttestationError::HardwareAccessFailed(format!(
            "inblob write race detected: generation={}",
            generation
        )));
    }

    // The temp dir is cleaned up by the Drop impl of tempfile
    // But ConfigFS dirs need rmdir, not recursive delete
    let path = temp_dir.into_path();
    let _ = std::fs::remove_dir(&path);

    Ok(quote)
}

/// Generate quote via /dev/tdx_guest ioctl (fallback).
fn generate_quote_ioctl(report_data: &[u8; 64]) -> Result<Vec<u8>> {
    use std::fs::OpenOptions;
    use std::os::unix::io::AsRawFd;

    let dev = OpenOptions::new()
        .read(true)
        .write(true)
        .open(TDX_GUEST_DEV)
        .map_err(|e| {
            AttestationError::HardwareAccessFailed(format!("open {}: {}", TDX_GUEST_DEV, e))
        })?;

    // TDX_CMD_GET_REPORT0 ioctl
    const TDX_CMD_GET_REPORT0: u64 = 0xC0405401;

    #[repr(C)]
    struct TdxReportReq {
        report_data: [u8; 64],
        td_report: [u8; 1024],
    }

    let mut req = TdxReportReq {
        report_data: [0u8; 64],
        td_report: [0u8; 1024],
    };
    req.report_data.copy_from_slice(report_data);

    let ret = unsafe {
        libc::ioctl(dev.as_raw_fd(), TDX_CMD_GET_REPORT0, &mut req as *mut _)
    };

    if ret != 0 {
        return Err(AttestationError::HardwareAccessFailed(format!(
            "TDX_CMD_GET_REPORT0 ioctl failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(req.td_report.to_vec())
}

/// Read CC eventlog from ACPI CCEL table.
fn read_eventlog() -> Result<Option<String>> {
    if !Path::new(CCEL_DATA_PATH).exists() {
        return Ok(None);
    }

    let data = std::fs::read(CCEL_DATA_PATH).map_err(|e| {
        AttestationError::HardwareAccessFailed(format!("read CCEL: {}", e))
    })?;

    if data.is_empty() {
        return Ok(None);
    }

    Ok(Some(BASE64.encode(&data)))
}
