use std::fs;
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::path::Path;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

use crate::error::{AttestationError, Result};
use crate::utils::pad_report_data;

use super::evidence::TdxEvidence;

const TSM_REPORT_PATH: &str = "/sys/kernel/config/tsm/report";
const TDX_GUEST_DEV: &str = "/dev/tdx_guest";
const CCEL_DATA_PATH: &str = "/sys/firmware/acpi/tables/data/CCEL";

/// Default QGS vsock port (matches Intel DCAP default).
const QGS_VSOCK_PORT: u32 = 4050;
/// VMADDR_CID_HOST
const VSOCK_CID_HOST: u32 = 2;
/// AF_VSOCK (Linux)
const AF_VSOCK: i32 = 40;
/// TDREPORT size in bytes.
const TDREPORT_SIZE: u32 = 1024;

// QGS message types
const QGS_MSG_GET_QUOTE_REQ: u32 = 0;
const QGS_MSG_GET_QUOTE_RESP: u32 = 1;

/// Controls how TDX quotes are generated.
///
/// The kernel's ConfigFS TSM path suffers from a 1-second polling loop
/// (`msleep_interruptible(MSEC_PER_SEC)` in `drivers/virt/coco/tdx-guest/tdx-guest.c`),
/// bottlenecking quote generation to ~1/sec even though the actual QGS/TDQE
/// signing takes only 2-4ms. The vsock bypass avoids this by speaking the QGS
/// wire protocol directly over AF_VSOCK.
///
/// # When to use each method
///
/// - **`Auto`** (default): Tries vsock first for speed, falls back to ConfigFS
///   if vsock is unavailable (no `vhost-vsock-pci` device, no QGS, etc.).
///   Best for bare-metal and self-hosted environments with QGS.
///
/// - **`Vsock`**: Forces vsock only. Fails if QGS is not reachable. Use when
///   you know vsock is available and want to avoid the ConfigFS fallback path.
///
/// - **`ConfigFs`**: Forces the kernel ConfigFS TSM path. Use on cloud platforms
///   (GCP, Kata/CoCo) where the hypervisor mediates quote generation through
///   QEMU's `quote-generation-socket` and guest-initiated vsock to QGS is not
///   available. This is ~1015ms per quote due to the kernel polling loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TdxQuoteMethod {
    /// Try vsock first (~2-4ms), fall back to ConfigFS TSM (~1015ms), then ioctl.
    #[default]
    Auto,
    /// Direct vsock to QGS only. Requires `vhost-vsock-pci` device and QGS on host.
    Vsock,
    /// Kernel ConfigFS TSM only. Works on GCP, Kata/CoCo, and any environment
    /// where the hypervisor routes quote requests via QEMU.
    ConfigFs,
}

/// Check if TDX hardware is available.
pub fn is_available() -> bool {
    // Check ConfigFS TSM with tdx_guest provider, or /dev/tdx_guest
    check_tsm_provider() || Path::new(TDX_GUEST_DEV).exists()
}

fn check_tsm_provider() -> bool {
    let tsm_path = Path::new(TSM_REPORT_PATH);
    if !tsm_path.exists() {
        return false;
    }
    // Create a temporary entry to read the actual provider name.
    // The TSM subsystem is shared across platforms (SNP, TDX, etc.),
    // so we must verify the provider is tdx_guest.
    let temp_dir = match tempfile::tempdir_in(tsm_path) {
        Ok(d) => d,
        Err(_) => return false,
    };
    let provider = std::fs::read_to_string(temp_dir.path().join("provider")).unwrap_or_default();
    let is_tdx = provider.trim().contains("tdx_guest");
    // ConfigFS dirs need rmdir, not recursive delete
    let path = temp_dir.keep();
    if let Err(e) = std::fs::remove_dir(&path) {
        log::warn!(
            "failed to clean up ConfigFS TSM report dir {:?}: {}",
            path,
            e
        );
    }
    is_tdx
}

/// Generate TDX attestation evidence using the default quote method ([`TdxQuoteMethod::Auto`]).
///
/// Equivalent to `generate_evidence_with(report_data, TdxQuoteMethod::Auto)`.
pub async fn generate_evidence(report_data: &[u8]) -> Result<TdxEvidence> {
    generate_evidence_with(report_data, TdxQuoteMethod::Auto).await
}

/// Generate TDX attestation evidence using the specified quote method.
///
/// See [`TdxQuoteMethod`] for when to use each method.
pub async fn generate_evidence_with(
    report_data: &[u8],
    method: TdxQuoteMethod,
) -> Result<TdxEvidence> {
    let padded = pad_report_data(report_data, 64)?;
    let padded_arr: [u8; 64] = padded
        .try_into()
        .map_err(|_| AttestationError::ReportDataTooLarge { max: 64 })?;

    let quote_bytes = match method {
        TdxQuoteMethod::Auto => generate_quote_auto(&padded_arr)?,
        TdxQuoteMethod::Vsock => {
            let q = generate_quote_vsock(&padded_arr)?;
            log::info!("TDX quote generated via vsock bypass");
            q
        }
        TdxQuoteMethod::ConfigFs => {
            let q = generate_quote_tsm(&padded_arr)?;
            log::info!("TDX quote generated via ConfigFS TSM");
            q
        }
    };

    let quote = BASE64.encode(&quote_bytes);

    // Read CC eventlog if available
    let cc_eventlog = read_eventlog().ok().flatten();

    Ok(TdxEvidence { quote, cc_eventlog })
}

/// Auto fallback chain: vsock (~2-4ms) → ConfigFS TSM (~1015ms) → ioctl (TDREPORT only).
fn generate_quote_auto(report_data: &[u8; 64]) -> Result<Vec<u8>> {
    match generate_quote_vsock(report_data) {
        Ok(q) => {
            log::info!("TDX quote generated via vsock bypass");
            Ok(q)
        }
        Err(e) => {
            log::debug!("vsock quote generation failed, falling back to ConfigFS: {e}");
            match generate_quote_tsm(report_data) {
                Ok(q) => {
                    log::info!("TDX quote generated via ConfigFS TSM");
                    Ok(q)
                }
                Err(e2) => {
                    log::debug!(
                        "ConfigFS quote generation failed, falling back to ioctl: {e2}"
                    );
                    generate_quote_ioctl(report_data)
                }
            }
        }
    }
}

/// Generate quote via Linux ConfigFS TSM reports.
fn generate_quote_tsm(report_data: &[u8; 64]) -> Result<Vec<u8>> {
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
    let provider = fs::read_to_string(report_path.join("provider"))
        .map_err(|e| AttestationError::HardwareAccessFailed(format!("read TSM provider: {}", e)))?;

    if !provider.trim().contains("tdx_guest") {
        // Clean up and leave the temp dir (will be cleaned by Drop)
        return Err(AttestationError::HardwareAccessFailed(format!(
            "TSM provider is '{}', not tdx_guest",
            provider.trim()
        )));
    }

    // Write report_data to inblob
    fs::write(report_path.join("inblob"), report_data)
        .map_err(|e| AttestationError::HardwareAccessFailed(format!("write inblob: {}", e)))?;

    // Read quote from outblob
    let quote = fs::read(report_path.join("outblob"))
        .map_err(|e| AttestationError::HardwareAccessFailed(format!("read outblob: {}", e)))?;

    // Check generation counter for race detection
    let gen_str = fs::read_to_string(report_path.join("generation"))
        .map_err(|e| AttestationError::HardwareAccessFailed(format!("read generation: {}", e)))?;

    let generation: u32 = gen_str
        .trim()
        .parse()
        .map_err(|e| AttestationError::HardwareAccessFailed(format!("parse generation: {}", e)))?;

    if generation > 1 {
        return Err(AttestationError::HardwareAccessFailed(format!(
            "inblob write race detected: generation={}",
            generation
        )));
    }

    // The temp dir is cleaned up by the Drop impl of tempfile
    // But ConfigFS dirs need rmdir, not recursive delete
    let path = temp_dir.keep();
    if let Err(e) = std::fs::remove_dir(&path) {
        log::warn!(
            "failed to clean up ConfigFS TSM report dir {:?}: {}",
            path,
            e
        );
    }

    Ok(quote)
}

/// Generate a TDREPORT via /dev/tdx_guest ioctl.
///
/// Returns the raw 1024-byte TDREPORT. This is a local attestation artifact
/// (not remotely verifiable on its own) but is the input needed by QGS to
/// produce a signed quote.
fn generate_tdreport(report_data: &[u8; 64]) -> Result<[u8; 1024]> {
    let dev = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(TDX_GUEST_DEV)
        .map_err(|e| {
            AttestationError::HardwareAccessFailed(format!("open {}: {}", TDX_GUEST_DEV, e))
        })?;

    // TDX_CMD_GET_REPORT0 = _IOWR('T', 1, struct tdx_report_req)
    // struct tdx_report_req = report_data[64] + td_report[1024] = 1088 bytes
    const TDX_CMD_GET_REPORT0: u64 = 0xC4405401;

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

    // SAFETY: TdxReportReq is repr(C) with fixed-size arrays matching the kernel
    // ioctl struct layout. The ioctl writes exactly 1024 bytes into td_report.
    let ret = unsafe { libc::ioctl(dev.as_raw_fd(), TDX_CMD_GET_REPORT0, &mut req as *mut _) };

    if ret != 0 {
        return Err(AttestationError::HardwareAccessFailed(format!(
            "TDX_CMD_GET_REPORT0 ioctl failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(req.td_report)
}

/// Generate quote via /dev/tdx_guest ioctl (fallback — returns TDREPORT only).
fn generate_quote_ioctl(report_data: &[u8; 64]) -> Result<Vec<u8>> {
    let report = generate_tdreport(report_data)?;
    Ok(report.to_vec())
}

/// Generate a signed TDX quote via direct vsock connection to QGS.
///
/// This bypasses the kernel's ConfigFS TSM path (and its 1-second polling
/// loop) by speaking the QGS wire protocol directly over AF_VSOCK. The
/// TDREPORT is obtained via the /dev/tdx_guest ioctl (instant), then sent
/// to QGS which returns a signed ECDSA-P256 quote in ~2-4ms.
///
/// Wire protocol (matching Intel DCAP `tdx_attest.c`):
///   Outer framing: 4-byte big-endian total body size + body
///   Request body:  qgs_msg_header (16 bytes) + report_size (u32) +
///                  id_list_size (u32) + TDREPORT (1024 bytes)
///   Response body: qgs_msg_header (16 bytes) + selected_id_size (u32) +
///                  quote_size (u32) + quote bytes
fn generate_quote_vsock(report_data: &[u8; 64]) -> Result<Vec<u8>> {
    // Step 1: Get TDREPORT from hardware (instant, ~2ms)
    let tdreport = generate_tdreport(report_data)?;

    // Step 2: Build QGS GetQuote request
    let qgs_request = build_qgs_get_quote_request(&tdreport)?;

    // Step 3: Send over vsock and receive response
    let qgs_response = vsock_send_receive(&qgs_request)?;

    // Step 4: Parse the quote out of the QGS response
    parse_qgs_get_quote_response(&qgs_response)
}

/// Build a QGS GetQuote request message with outer framing.
fn build_qgs_get_quote_request(tdreport: &[u8; 1024]) -> Result<Vec<u8>> {
    // Inner message: header (16) + report_size (4) + id_list_size (4) + tdreport (1024)
    let inner_size: u32 = 16 + 4 + 4 + TDREPORT_SIZE;

    let mut msg = Vec::with_capacity(4 + inner_size as usize);

    // Outer framing: 4-byte big-endian body size
    msg.extend_from_slice(&inner_size.to_be_bytes());

    // QGS message header (16 bytes)
    msg.extend_from_slice(&1u16.to_le_bytes()); // major_version = 1
    msg.extend_from_slice(&0u16.to_le_bytes()); // minor_version = 0
    msg.extend_from_slice(&QGS_MSG_GET_QUOTE_REQ.to_le_bytes()); // type = GET_QUOTE_REQ
    msg.extend_from_slice(&inner_size.to_le_bytes()); // size = total inner message size
    msg.extend_from_slice(&0u32.to_le_bytes()); // error_code = 0

    // Request payload
    msg.extend_from_slice(&TDREPORT_SIZE.to_le_bytes()); // report_size = 1024
    msg.extend_from_slice(&0u32.to_le_bytes()); // id_list_size = 0
    msg.extend_from_slice(tdreport); // TDREPORT bytes

    Ok(msg)
}

/// Open AF_VSOCK to QGS on the host (CID 2, port 4050), send request, receive response.
fn vsock_send_receive(request: &[u8]) -> Result<Vec<u8>> {
    // SAFETY: Creating a vsock socket — standard socket syscall, no
    // memory-safety concerns beyond the returned fd.
    let fd = unsafe { libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(AttestationError::HardwareAccessFailed(format!(
            "vsock socket creation failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    // Wrap in a File so the fd is closed on drop. std::fs::File implements
    // Read + Write on any fd and will close it on drop.
    // SAFETY: fd is a valid socket descriptor returned by libc::socket above.
    let mut sock: fs::File = unsafe { std::os::fd::FromRawFd::from_raw_fd(fd) };

    // Connect to QGS on host
    #[repr(C)]
    struct SockaddrVm {
        svm_family: libc::sa_family_t,
        svm_reserved1: u16,
        svm_port: u32,
        svm_cid: u32,
        svm_flags: u8,
        svm_zero: [u8; 3],
    }

    let addr = SockaddrVm {
        svm_family: AF_VSOCK as libc::sa_family_t,
        svm_reserved1: 0,
        svm_port: QGS_VSOCK_PORT,
        svm_cid: VSOCK_CID_HOST,
        svm_flags: 0,
        svm_zero: [0; 3],
    };

    // SAFETY: addr is repr(C), correctly sized for sockaddr_vm. The fd is a
    // valid vsock socket.
    let ret = unsafe {
        libc::connect(
            fd,
            &addr as *const SockaddrVm as *const libc::sockaddr,
            std::mem::size_of::<SockaddrVm>() as libc::socklen_t,
        )
    };

    if ret != 0 {
        return Err(AttestationError::HardwareAccessFailed(format!(
            "vsock connect to CID {}:{} failed: {}",
            VSOCK_CID_HOST,
            QGS_VSOCK_PORT,
            std::io::Error::last_os_error()
        )));
    }

    // Set a 10-second timeout for the full exchange
    let timeout = libc::timeval {
        tv_sec: 10,
        tv_usec: 0,
    };
    // SAFETY: Standard setsockopt call with a correctly-typed timeval struct.
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeout as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            &timeout as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    // Send the full request
    sock.write_all(request).map_err(|e| {
        AttestationError::HardwareAccessFailed(format!("vsock send failed: {}", e))
    })?;

    // Read 4-byte size header
    let mut size_buf = [0u8; 4];
    sock.read_exact(&mut size_buf).map_err(|e| {
        AttestationError::HardwareAccessFailed(format!("vsock read response size failed: {}", e))
    })?;

    let body_size = u32::from_be_bytes(size_buf) as usize;

    // Sanity check: response should be between 16 bytes (header only) and 64KB
    if body_size < 16 || body_size > 65536 {
        return Err(AttestationError::HardwareAccessFailed(format!(
            "vsock response body size out of range: {}",
            body_size
        )));
    }

    // Read the full body
    let mut body = vec![0u8; body_size];
    sock.read_exact(&mut body).map_err(|e| {
        AttestationError::HardwareAccessFailed(format!("vsock read response body failed: {}", e))
    })?;

    Ok(body)
}

/// Parse a QGS GetQuote response and extract the quote bytes.
fn parse_qgs_get_quote_response(response: &[u8]) -> Result<Vec<u8>> {
    // Minimum: header (16) + selected_id_size (4) + quote_size (4) = 24
    if response.len() < 24 {
        return Err(AttestationError::HardwareAccessFailed(format!(
            "QGS response too short: {} bytes",
            response.len()
        )));
    }

    // Parse header
    let major = u16::from_le_bytes([response[0], response[1]]);
    let _minor = u16::from_le_bytes([response[2], response[3]]);
    let msg_type = u32::from_le_bytes([response[4], response[5], response[6], response[7]]);
    let _msg_size = u32::from_le_bytes([response[8], response[9], response[10], response[11]]);
    let error_code = u32::from_le_bytes([response[12], response[13], response[14], response[15]]);

    if major != 1 {
        return Err(AttestationError::HardwareAccessFailed(format!(
            "QGS response: unsupported major version {}",
            major
        )));
    }

    if msg_type != QGS_MSG_GET_QUOTE_RESP {
        return Err(AttestationError::HardwareAccessFailed(format!(
            "QGS response: unexpected message type {} (expected {})",
            msg_type, QGS_MSG_GET_QUOTE_RESP
        )));
    }

    if error_code != 0 {
        return Err(AttestationError::HardwareAccessFailed(format!(
            "QGS returned error code {}",
            error_code
        )));
    }

    // Parse payload: selected_id_size (u32) + quote_size (u32) + data
    let selected_id_size =
        u32::from_le_bytes([response[16], response[17], response[18], response[19]]) as usize;
    let quote_size =
        u32::from_le_bytes([response[20], response[21], response[22], response[23]]) as usize;

    if quote_size == 0 {
        return Err(AttestationError::HardwareAccessFailed(
            "QGS returned empty quote".to_string(),
        ));
    }

    let quote_offset = 24 + selected_id_size;
    let quote_end = quote_offset + quote_size;

    if quote_end > response.len() {
        return Err(AttestationError::HardwareAccessFailed(format!(
            "QGS response truncated: need {} bytes, have {}",
            quote_end,
            response.len()
        )));
    }

    Ok(response[quote_offset..quote_end].to_vec())
}

/// Read CC eventlog from ACPI CCEL table.
fn read_eventlog() -> Result<Option<String>> {
    if !Path::new(CCEL_DATA_PATH).exists() {
        return Ok(None);
    }

    let data = std::fs::read(CCEL_DATA_PATH)
        .map_err(|e| AttestationError::HardwareAccessFailed(format!("read CCEL: {}", e)))?;

    if data.is_empty() {
        return Ok(None);
    }

    Ok(Some(BASE64.encode(&data)))
}
