pub use vtpm_attestation::hcl;

pub use vtpm_attestation::quote;

use thiserror::Error;
#[cfg(feature = "attester")]
pub use vtpm_attestation::vtpm;

#[derive(Error, Debug)]
pub enum HttpError {
    #[error("HTTP error")]
    Http(#[from] reqwest::Error),
    #[error("failed to read HTTP response")]
    Io(#[from] std::io::Error),
}

/// Determines if the current VM is an SEV-SNP CVM.
/// Returns `Ok(true)` if the VM is an SEV-SNP CVM, `Ok(false)` if it is not,
/// and `Err` if an error occurs.
/// #[cfg(feature = "attester")]
#[cfg(feature = "attester")]
pub fn is_snp_cvm() -> Result<bool, vtpm::ReportError> {
    let bytes = vtpm::get_report()?;
    let Ok(hcl_report) = hcl::HclReport::new(bytes) else {
        return Ok(false);
    };
    let is_snp = hcl_report.report_type() == hcl::ReportType::Snp;
    Ok(is_snp)
}

#[cfg(feature = "verifier")]
pub mod amd_kds;
#[cfg(feature = "verifier")]
pub mod certs;
pub mod imds;
pub mod report;
