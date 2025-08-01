use crate::coco::snp::{
    legacy_device::Firmware,
    types::{CertTableEntry, DerivedKey, GuestFieldSelect},
};
use crate::coco::{Device, ReportRequest, ReportResponse};
use crate::error::{CocoError, Result};

use std::any::Any;

#[derive(Clone, Copy, Debug)]
pub struct Legacy {}

impl Device for Legacy {
    fn as_any(&self) -> &dyn Any {
        self
    }

    /// Get attestation report via /dev/sev-guest device
    fn get_report(&self, req: &ReportRequest) -> Result<ReportResponse> {
        // Try to open /dev/sev-guest
        let mut fw = Firmware::open()?;
        let report = fw.get_report(None, req.report_data, req.vmpl)?;
        let report = report.to_vec();
        Ok(ReportResponse {
            report,
            var_data: None,
        })
    }
}

impl Legacy {
    pub fn new() -> Self {
        Legacy {}
    }

    pub fn get_certificates(&self) -> Result<Vec<CertTableEntry>> {
        let mut fw: Firmware = Firmware::open()?;

        // Generate random request data
        let request_data: [u8; 64] = crate::utils::generate_random_data();

        // Call get_ext_report, drop the attestation report and only care about the certs it returns.
        let (_, certificates) = fw.get_ext_report(None, Some(request_data), None)?;

        if certificates.is_some() {
            return Ok(certificates.unwrap());
        }

        Err(CocoError::Firmware(
            "No certificates were loaded by the host!".to_string(),
        ))
    }

    pub fn get_derived_key(
        &self,
        root_key_sel: bool,
        vmpl: u32,
        guest_field_sel: u64,
        guest_svn: u32,
        tcb_version: u64,
    ) -> Result<[u8; 32]> {
        let request = DerivedKey::new(
            root_key_sel,
            GuestFieldSelect(guest_field_sel),
            vmpl,
            guest_svn,
            tcb_version,
        );
        // Try to open device
        let mut sev_fw = Firmware::open()?;
        // Try to get derived key
        Ok(sev_fw.get_derived_key(None, request)?)
    }
}
