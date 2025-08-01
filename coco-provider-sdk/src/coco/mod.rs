#[cfg(feature = "configfs")]
pub mod configfs;
#[cfg(feature = "legacy")]
pub mod legacy;
pub mod mock;
pub mod snp;
#[cfg(all(feature = "tpm", target_os = "linux"))]
pub mod tpm;

use crate::cpu::CpuVendor;
use crate::error::{CocoError, Result};
#[cfg(feature = "configfs")]
use crate::utils::generate_random_number;
use std::any::Any;
use std::fmt::Debug;
#[cfg(feature = "configfs")]
use std::fs::{create_dir_all, remove_dir};
#[cfg(any(
    feature = "configfs",
    feature = "legacy",
    all(feature = "tpm", target_os = "linux")
))]
use std::path::Path;

#[cfg(feature = "configfs")]
const CONFIGFS_BASE_PATH: &str = "/sys/kernel/config/tsm/report";
#[cfg(feature = "legacy")]
const SEV_LEGACY_PATH: &str = "/dev/sev-guest";
#[cfg(all(feature = "tpm", target_os = "linux"))]
const TPM_PATHS: [&str; 2] = ["/dev/tpm0", "/dev/tpmrm0"];

pub trait Device: Debug {
    /// Retrieve attestation report from the underlying device.
    ///
    /// ## Returns:
    /// * `Vec<u8>` - The report as raw bytes.
    /// * `Error` - If there are issues with the device or any parameters passed
    /// to the device.
    fn get_report(&self, req: &ReportRequest) -> Result<ReportResponse>;

    fn as_any(&self) -> &dyn Any;
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum CocoDeviceType {
    /// Coco device is available via configfs
    ConfigFs = 0,
    /// Coco device is available via legacy interface
    /// Only applicable to AMD /dev/sev_guest
    Legacy = 1,
    /// Coco device is exposed via Tpm chip.
    /// For now, the only provider that uses this is Azure.
    Tpm = 2,
    /// CoCo device not available, use a mock device.
    /// For testing purposes only.
    Mock = 3,
}

/// Struct to request information from a CoCo device
pub struct ReportRequest {
    /// Nonce to provide for the report
    pub report_data: Option<[u8; 64]>,
    /// Privilege level to use for the report.
    /// Only applies to SEV-SNP. Must be a value between 0-3.
    pub vmpl: Option<u32>,
}

/// Struct to encapsulate response from a CoCo device
pub struct ReportResponse {
    /// Raw attestation report as bytes.
    pub report: Vec<u8>,
    /// Only applicable to Azure vTPM.
    /// Provides the HCLAkPub/HCLEkPub/other stuff that goes into Azure's report_data
    pub var_data: Option<Vec<u8>>,
}

/// Get the type of CoCo device available on the system.
/// ## Parameters
/// * `vendor` - CPU vendor
///
/// ## Returns
/// * `CocoDeviceType` - Type of CoCo device available
pub fn get_device_type(vendor: &CpuVendor) -> Result<CocoDeviceType> {
    if vendor == &CpuVendor::Arm {
        return Err(CocoError::Firmware(
            "Arm CoCo is not supported yet. Maybe next time.".to_string(),
        ));
    }
    // Prefer configfs over legacy if it exists, and configfs feature is enabled.
    #[cfg(feature = "configfs")]
    if Path::new(CONFIGFS_BASE_PATH).exists() {
        if try_create_configfs_report_folder() {
            return Ok(CocoDeviceType::ConfigFs);
        }
    }
    // Check for legacy device only if it's AMD, and legacy feature is enabled.
    #[cfg(feature = "legacy")]
    if vendor == &CpuVendor::Amd && Path::new(SEV_LEGACY_PATH).exists() {
        return Ok(CocoDeviceType::Legacy);
    }
    // Else check if TPM is available, and if the tpm feature is enabled.
    // must also be a linux platform.
    #[cfg(all(feature = "tpm", target_os = "linux"))]
    for path in TPM_PATHS.iter() {
        if Path::new(path).exists() {
            return Ok(CocoDeviceType::Tpm);
        }
    }
    // If not, return a Mock device type.
    Ok(CocoDeviceType::Mock)
}

#[cfg(feature = "configfs")]
/// Initial test to see if we can create a folder in configfs
/// If we are unable to, it means the device does not exist,
/// or we do not have the right permissions.
fn try_create_configfs_report_folder() -> bool {
    let rand_num = generate_random_number();
    let device_path = format!("{}/report-{}", CONFIGFS_BASE_PATH, rand_num);
    if create_dir_all(&device_path).is_ok() {
        if remove_dir(device_path).is_ok() {
            return true;
        }
    }
    false
}
