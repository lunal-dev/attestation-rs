#[derive(Debug, PartialEq, Copy, Clone)]
pub enum Hypervisor {
    Kvm,
    HyperV,
    None,
    Unknown,
}

#[cfg(target_arch = "x86_64")]
pub mod amd64 {
    use super::Hypervisor;
    use crate::error::{CocoError, Result};
    use std::arch::x86_64::__cpuid;

    // References:
    // https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/feature-discovery

    const CPUID_KVM_SIG: &str = "KVMKVMKVM\0\0\0";

    const CPUID_FEATURE_HYPERVISOR: u32 = 1 << 31;
    const CPUID_PROCESSOR_INFO_AND_FEATURE_BITS: u32 = 0x1;
    const CPUID_HYPERVISOR_LEAF: u32 = 0x40000000;
    const CPUID_GET_HIGHEST_FUNCTION: u32 = 0x80000000;

    const CPUID_HYPERV_SIG: &str = "Microsoft Hv";
    const CPUID_HYPERV_MIN: u32 = 0x40000005;
    const CPUID_HYPERV_MAX: u32 = 0x4000ffff;
    const CPUID_HYPERV_FEATURES: u32 = 0x40000003;
    const CPUID_HYPERV_ISOLATION: u32 = 1 << 22;
    const CPUID_HYPERV_CPU_MANAGEMENT: u32 = 1 << 12;

    const CPUID_HYPERV_ISOLATION_CONFIG: u32 = 0x4000000C;
    const CPUID_HYPERV_ISOLATION_TYPE_MASK: u32 = 0xf;

    #[derive(PartialEq, Copy, Clone)]
    #[repr(u32)]
    pub enum HypervIsolationType {
        Snp = 2,
        Tdx = 3,
    }

    pub fn get_hypervisor() -> Hypervisor {
        // First check if running under a hypervisor
        let cpuid = unsafe { __cpuid(CPUID_PROCESSOR_INFO_AND_FEATURE_BITS) };
        if (cpuid.ecx & CPUID_FEATURE_HYPERVISOR) == 0 {
            return Hypervisor::None;
        }

        let cpuid = unsafe { __cpuid(CPUID_HYPERVISOR_LEAF) };
        let mut sig: Vec<u8> = vec![];
        sig.append(&mut cpuid.ebx.to_le_bytes().to_vec());
        sig.append(&mut cpuid.ecx.to_le_bytes().to_vec());
        sig.append(&mut cpuid.edx.to_le_bytes().to_vec());

        if sig == CPUID_HYPERV_SIG.as_bytes() && hyperv_extended_checks() {
            return Hypervisor::HyperV;
        } else if sig == CPUID_KVM_SIG.as_bytes() {
            return Hypervisor::Kvm;
        }

        Hypervisor::Unknown
    }

    fn hyperv_extended_checks() -> bool {
        let mut cpuid = unsafe { __cpuid(CPUID_GET_HIGHEST_FUNCTION) };
        if cpuid.eax < CPUID_HYPERVISOR_LEAF {
            return false;
        }

        cpuid = unsafe { __cpuid(CPUID_HYPERVISOR_LEAF) };
        if cpuid.eax < CPUID_HYPERV_MIN || cpuid.eax > CPUID_HYPERV_MAX {
            return false;
        }

        cpuid = unsafe { __cpuid(CPUID_HYPERV_FEATURES) };

        let isolated: bool = (cpuid.ebx & CPUID_HYPERV_ISOLATION) != 0;
        let managed: bool = (cpuid.ebx & CPUID_HYPERV_CPU_MANAGEMENT) != 0;

        if !isolated || managed {
            return false;
        }
        true
    }

    /// Double check if HyperV supports SEV_SNP or TDX.
    pub fn hyperv_extra_isolation_checks(isolation_type: &HypervIsolationType) -> Result<()> {
        let cpuid = unsafe { __cpuid(CPUID_HYPERV_ISOLATION_CONFIG) };
        let mask = cpuid.ebx & CPUID_HYPERV_ISOLATION_TYPE_MASK;

        if mask != *isolation_type as u32 {
            return Err(CocoError::Firmware(format!(
                "Isolation type does not match! mask: {}, Isolation Type: {}",
                mask, *isolation_type as u32
            )));
        }
        Ok(())
    }
}

#[cfg(target_arch = "aarch64")]
pub mod arm64 {
    use super::Hypervisor;

    pub fn get_hypervisor() -> Hypervisor {
        // TODO: Arm doesn't use CPUID like x86_64.
        Hypervisor::Unknown
    }
}
