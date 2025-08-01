use super::{Device, ReportRequest, ReportResponse};
use crate::cpu::CpuVendor;
use crate::error::{CocoError, Result};
use crate::hypervisor::Hypervisor;
use std::mem::size_of;

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::any::Any;
use tss_esapi::{
    abstraction::nv,
    handles::NvIndexTpmHandle,
    interface_types::{resource_handles::NvAuth, session_handles::AuthSession},
    tcti_ldr::{DeviceConfig, TctiNameConf},
};

/// Non-volatile index used to read the attestation report.
/// For AMD, the report in the Hcl Report is already signed.
/// For Intel, the report is unsigned, and still needs to be turned into a quote.
const VTPM_HCL_REPORT_NV_INDEX: u32 = 0x01400001;
const SNP_REPORT_TYPE: u32 = 2;
const TDX_REPORT_TYPE: u32 = 4;

#[repr(C)]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
struct TdReport {
    #[serde(with = "BigArray")]
    report_mac: [u8; 256],
    #[serde(with = "BigArray")]
    tee_tcb_info: [u8; 239],
    reserved: [u8; 17],
    #[serde(with = "BigArray")]
    tdinfo: [u8; 512],
}

const fn max(a: usize, b: usize) -> usize {
    if a > b {
        return a;
    }
    b
}
const TD_REPORT_SIZE: usize = size_of::<TdReport>();
const SNP_REPORT_SIZE: usize = 1184; // See AMD SEV-SNP specification
const MAX_REPORT_SIZE: usize = max(TD_REPORT_SIZE, SNP_REPORT_SIZE);
const VARIABLE_DATA_OFFSET: usize = size_of::<HclReport>();

#[repr(C)]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
struct HclReport {
    pub header: HclHeader,
    #[serde(with = "BigArray")]
    pub report: [u8; MAX_REPORT_SIZE],
    pub footer: HclFooter,
}

#[repr(C)]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
struct HclHeader {
    signature: u32,
    version: u32,
    pub report_size: u32,
    request_type: u32,
    status: u32,
    reserved: [u32; 3],
}

#[repr(C)]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
struct HclFooter {
    data_size: u32,
    version: u32,
    pub report_type: u32,
    report_data_hash_type: HashType,
    variable_data_size: u32,
    #[serde(skip)]
    /// On Azure, this field is used to hold the HCLAkPub and HCLEkPub.
    variable_data: [u8; 0],
}

#[repr(u32)]
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq)]
enum HashType {
    Invalid = 0,
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Debug)]
pub struct Tpm {
    vendor: CpuVendor,
    hypervisor: Hypervisor,
}

impl Tpm {
    pub fn new(vendor: CpuVendor, hypervisor: Hypervisor) -> Result<Self> {
        let mut ctx = tss_esapi::Context::new(TctiNameConf::Device(DeviceConfig::default()))?;
        ctx.set_sessions((Some(AuthSession::Password), None, None));
        Ok(Tpm { vendor, hypervisor })
    }

    fn tpm2_read(&self) -> Result<Vec<u8>> {
        let handle = NvIndexTpmHandle::new(VTPM_HCL_REPORT_NV_INDEX)?;
        let mut ctx = tss_esapi::Context::new(TctiNameConf::Device(DeviceConfig::default()))?;
        ctx.set_sessions((Some(AuthSession::Password), None, None));
        Ok(nv::read_full(&mut ctx, NvAuth::Owner, handle)?)
    }
}

impl Device for Tpm {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn get_report(&self, req: &ReportRequest) -> Result<ReportResponse> {
        if self.vendor == CpuVendor::Amd && self.hypervisor == Hypervisor::HyperV {
            if req.vmpl.is_some_and(|v| v > 0) {
                return Err(CocoError::Tpm(
                    "HyperV vTPM attestation report requires VMPL 0!".to_string(),
                ));
            }
        }
        if req.report_data.is_some() {
            return Err(CocoError::Tpm(
                "TPM does not support report_data".to_string(),
            ));
        }
        let bytes = self.tpm2_read()?;
        let report: HclReport = bincode::deserialize(&bytes)?;

        // Get the variable data if it exists.
        let var_data_size = report.footer.variable_data_size;
        if var_data_size <= 0 {
            return Err(CocoError::Tpm(
                "No variable_data section found!".to_string(),
            ));
        }
        let var_data_bytes =
            bytes[VARIABLE_DATA_OFFSET..VARIABLE_DATA_OFFSET + var_data_size as usize].to_vec();

        // Perform additional checks on the report.
        match self.vendor {
            CpuVendor::Amd => {
                if report.footer.report_type != SNP_REPORT_TYPE {
                    return Err(CocoError::Tpm(
                        "AMD vTPM attestation report must be of type SNP!".to_string(),
                    ));
                }
            }
            CpuVendor::Intel => {
                if report.footer.report_type != TDX_REPORT_TYPE {
                    return Err(CocoError::Tpm(
                        "Intel vTPM attestation report must be of type TDX!".to_string(),
                    ));
                }
            }
            _ => {}
        }

        Ok(ReportResponse {
            report: match self.vendor {
                CpuVendor::Amd => report.report[0..SNP_REPORT_SIZE].to_vec(),
                CpuVendor::Intel => report.report[0..TD_REPORT_SIZE].to_vec(),
                _ => return Err(CocoError::Tpm("Unsupported CPU vendor!".to_string())),
            },
            var_data: Some(var_data_bytes),
        })
    }
}
