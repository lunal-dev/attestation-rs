use crate::coco::{Device, ReportRequest, ReportResponse};
use crate::error::Result;
use std::any::Any;

#[derive(Clone, Copy, Debug)]
pub struct Mock {}

impl Device for Mock {
    fn as_any(&self) -> &dyn Any {
        self
    }

    /// Get a mock attestation report
    fn get_report(&self, _req: &ReportRequest) -> Result<ReportResponse> {
        Ok(ReportResponse {
            report: vec![0; 64],
            var_data: None,
        })
    }
}

impl Mock {
    pub fn new() -> Self {
        Mock {}
    }
}
