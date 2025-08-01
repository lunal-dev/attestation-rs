#[cfg(target_arch = "x86_64")]
use crate::error::{CocoError, Result};
use sysinfo::System;

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::__cpuid;

#[cfg(target_arch = "x86_64")]
const TDX_CPUID_LEAF_ID: u64 = 0x21;

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum CpuArchitecture {
    X64,
    Arm64,
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum CpuVendor {
    Intel = 0,
    Amd = 1,
    Arm = 2,
    Unknown = 999,
}

/// Retrieve CPU Brand
pub fn get_model() -> String {
    let mut s = System::new_all();
    s.refresh_all();
    // Every PC will have at least one CPU.
    s.cpus()[0].brand().to_string()
}

/// Retrieve CPU Architecture
pub fn get_architecture() -> CpuArchitecture {
    #[cfg(target_arch = "x86_64")]
    return CpuArchitecture::X64;
    #[cfg(target_arch = "aarch64")]
    return CpuArchitecture::Arm64;
}

#[cfg(target_arch = "x86_64")]
/// Retrieve CPU Manufacturer
pub fn get_vendor() -> CpuVendor {
    let cpuid = unsafe { __cpuid(0x0) };

    if &cpuid.ebx.to_ne_bytes() == b"Genu"
        && &cpuid.edx.to_ne_bytes() == b"ineI"
        && &cpuid.ecx.to_ne_bytes() == b"ntel"
    {
        return CpuVendor::Intel;
    } else if &cpuid.ebx.to_ne_bytes() == b"Auth"
        && &cpuid.edx.to_ne_bytes() == b"enti"
        && &cpuid.ecx.to_ne_bytes() == b"cAMD"
    {
        return CpuVendor::Amd;
    }
    return CpuVendor::Unknown;
}

// TODO: WIP.
#[cfg(target_arch = "aarch64")]
pub fn get_vendor() -> CpuVendor {
    return CpuVendor::Arm;
}

#[cfg(target_arch = "x86_64")]
/// When running on Intel Processor, check whether Intel TDX is enabled on the guest.
pub fn check_tdx_enabled() -> Result<()> {
    let cpuid = unsafe { __cpuid(0) };
    // Check if legacy guest.
    let cpuid_leaf = cpuid.eax as u64;
    if cpuid_leaf < TDX_CPUID_LEAF_ID {
        return Err(CocoError::Firmware(
            "Legacy guest, Intel TDX not supported.".to_string(),
        ));
    }

    // Check presence of Intel TDX
    let cpuid = unsafe { __cpuid(TDX_CPUID_LEAF_ID as u32) };
    if &cpuid.ebx.to_ne_bytes() != b"Inte"
        || &cpuid.edx.to_ne_bytes() != b"lTDX"
        || &cpuid.ecx.to_ne_bytes() != b"    "
    {
        return Err(CocoError::Firmware(
            "Intel TDX not supported on this guest.".to_string(),
        ));
    }
    Ok(())
}
