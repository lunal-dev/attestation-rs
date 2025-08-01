pub mod coco;
pub mod cpu;
pub mod error;
pub mod hypervisor;
pub mod utils;

use utils::get_current_uid;

#[cfg(feature = "legacy")]
use coco::legacy::Legacy;
use coco::{get_device_type, CocoDeviceType, Device};
use cpu::{CpuArchitecture, CpuVendor};
use error::{CocoError, Result};
#[cfg(target_arch = "x86_64")]
use hypervisor::amd64::{get_hypervisor, hyperv_extra_isolation_checks, HypervIsolationType};
#[cfg(target_arch = "aarch64")]
use hypervisor::arm64::get_hypervisor;
use hypervisor::Hypervisor;

#[cfg(test)]
#[path = "./tests/lib-test.rs"]
mod lib_tests;

/// Struct to represent all information we need about the
/// Confidential Computing (coco) Provider.
#[derive(Debug)]
pub struct CocoProvider {
    /// VM architecture
    pub arch: CpuArchitecture,
    /// VM hypervisor
    pub hypervisor: Hypervisor,
    /// Cpu Vendor
    pub cpu_vendor: CpuVendor,
    /// CPU Model
    pub cpu_model: String,
    /// Type of hardware device exposed to the VM for coco
    pub device_type: CocoDeviceType,
    /// Handle to the device
    pub device: Box<dyn Device>,
    #[cfg(feature = "legacy")]
    /// AMD SEV-SNP Only, when device != TPM: Handle to the legacy device.
    /// This is hacked in as only the legacy device supports derived key generation.
    pub legacy_device: Option<Legacy>,
}

/// Retrieve the Confidential Computing (coco) provider information for your system.
///
/// Returns:
/// - CocoProvider object if everything runs as expected.
/// - Error when:
///   - The machine running this function is not running under a hypervisor.
///   - The machine runs under a hypervisor,
///     but the extensions required for confidential computing are not enabled.
///   - No confidential computing device exists.
///   - Running an unsupported architecture.
///   - Not running as root.
pub fn get_coco_provider() -> Result<CocoProvider> {
    if get_current_uid() != 0 {
        return Err(CocoError::Permission(
            "Please run this program as root to access CoCo device!".to_string(),
        ));
    }
    let arch = cpu::get_architecture();
    let cpu_vendor = cpu::get_vendor();
    let cpu_model = cpu::get_model();
    let hypervisor = get_hypervisor();
    #[allow(unused_mut)]
    let mut should_use_mock = match hypervisor {
        Hypervisor::None => true,
        Hypervisor::Unknown => true,
        _ => false,
    };
    // Perform additional checks before creating device.
    #[cfg(target_arch = "x86_64")]
    match cpu_vendor {
        CpuVendor::Intel => {
            if hypervisor == Hypervisor::HyperV {
                hyperv_extra_isolation_checks(&HypervIsolationType::Tdx)?;
            } else if hypervisor == Hypervisor::Kvm {
                if cpu::check_tdx_enabled().is_err() {
                    should_use_mock = true;
                }
            }
        }
        CpuVendor::Amd => {
            if hypervisor == Hypervisor::HyperV {
                hyperv_extra_isolation_checks(&HypervIsolationType::Snp)?;
            }
        }
        _ => {}
    }
    let device_type = match should_use_mock {
        true => CocoDeviceType::Mock,
        false => get_device_type(&cpu_vendor)?,
    };
    construct_coco_provider(device_type, arch, hypervisor, cpu_vendor, cpu_model)
}

fn construct_coco_provider(
    device_type: CocoDeviceType,
    arch: CpuArchitecture,
    hypervisor: Hypervisor,
    cpu_vendor: CpuVendor,
    cpu_model: String,
) -> Result<CocoProvider> {
    match device_type {
        CocoDeviceType::Mock => {
            return Ok(CocoProvider {
                arch,
                hypervisor,
                cpu_vendor,
                cpu_model,
                device_type,
                device: Box::new(coco::mock::Mock::new()),
                #[cfg(feature = "legacy")]
                legacy_device: None,
            });
        }
        CocoDeviceType::Legacy => {
            #[cfg(feature = "legacy")]
            {
                let device = coco::legacy::Legacy::new();
                let legacy_device = match cpu_vendor {
                    CpuVendor::Amd => Some(device),
                    _ => None,
                };
                return Ok(CocoProvider {
                    arch,
                    hypervisor,
                    cpu_vendor,
                    cpu_model,
                    device_type,
                    device: Box::new(device),
                    legacy_device,
                });
            }
            #[cfg(not(feature = "legacy"))]
            {
                return Err(CocoError::Firmware(
                    "Legacy feature not enabled!!!".to_string(),
                ));
            }
        }
        CocoDeviceType::ConfigFs => {
            #[cfg(all(feature = "configfs", feature = "legacy"))]
            {
                let device = coco::configfs::ConfigFs::new();
                let legacy_device = match cpu_vendor {
                    CpuVendor::Amd => Some(coco::legacy::Legacy::new()),
                    _ => None,
                };
                return Ok(CocoProvider {
                    arch,
                    hypervisor,
                    cpu_vendor,
                    cpu_model,
                    device_type,
                    device: Box::new(device),
                    legacy_device,
                });
            }
            // Note: this is not actually unreachable.
            // When using Intel TDX, legacy device does not exist, so we only enable configfs.
            #[allow(unreachable_code)]
            #[cfg(feature = "configfs")]
            {
                let device = coco::configfs::ConfigFs::new();
                return Ok(CocoProvider {
                    arch,
                    hypervisor,
                    cpu_vendor,
                    cpu_model,
                    device_type,
                    device: Box::new(device),
                    #[cfg(feature = "legacy")]
                    legacy_device: None,
                });
            }
            #[cfg(not(feature = "configfs"))]
            {
                return Err(CocoError::Firmware(
                    "ConfigFS feature not enabled!!!".to_string(),
                ));
            }
        }
        // CocoDeviceType::Tpm => {
        //     #[cfg(all(feature = "tpm", target_os = "linux"))]
        //     {
        //         let device = coco::tpm::Tpm::new(cpu_vendor, hypervisor)?;
        //         return Ok(CocoProvider {
        //             arch,
        //             hypervisor,
        //             cpu_vendor,
        //             cpu_model,
        //             device_type,
        //             device: Box::new(device),
        //             #[cfg(feature = "legacy")]
        //             legacy_device: None,
        //         });
        //     }
        //     #[allow(unreachable_code)]
        //     {
        //         return Err(CocoError::Firmware(
        //             "TPM feature not enabled or platform is not Linux!!!".to_string(),
        //         ));
        //     }
        // }
        // Leaving this here for now in case we want to expand to support new stuff.
        #[allow(unreachable_patterns)]
        _ => {
            return Err(CocoError::Firmware("Device type not supported".to_string()));
        }
    }
}

#[cfg(feature = "clib")]
pub mod c {
    use super::{get_coco_provider, CocoProvider};
    use crate::CocoDeviceType;
    use once_cell::sync::Lazy;
    use std::marker::{Send, Sync};
    use std::sync::Mutex;

    unsafe impl Send for CocoProvider {}
    unsafe impl Sync for CocoProvider {}

    static COCO_PROVIDER: Lazy<Mutex<CocoProvider>> =
        Lazy::new(|| Mutex::new(get_coco_provider().unwrap()));

    #[no_mangle]
    pub extern "C" fn get_vendor() -> u32 {
        match COCO_PROVIDER.lock() {
            Ok(provider) => provider.cpu_vendor as u32,
            Err(_) => 999,
        }
    }

    #[no_mangle]
    pub extern "C" fn get_coco_device_type() -> u32 {
        match COCO_PROVIDER.lock() {
            Ok(provider) => {
                if provider.device_type != CocoDeviceType::Mock {
                    return provider.device_type as u32;
                }
                return 999;
            }
            Err(_) => 999,
        }
    }
}
