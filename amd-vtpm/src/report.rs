// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(feature = "verifier")]
use super::certs::Vcek;
#[cfg(feature = "verifier")]
use p384::{
    // Changed from p256 to p384
    ecdsa::{Signature, VerifyingKey},
    PublicKey,
};
pub use sev::firmware::guest::AttestationReport;
#[cfg(feature = "verifier")]
use sha2::{Digest, Sha384};
#[cfg(feature = "verifier")]
use signature::DigestVerifier; // Changed to DigestVerifier
use thiserror::Error;
use vtpm_attestation::hcl::HclReport;
use vtpm_attestation::hcl::{self, SNP_REPORT_SIZE};
#[cfg(feature = "attester")]
use vtpm_attestation::vtpm;

#[derive(Error, Debug)]
pub enum ValidateError {
    #[cfg(feature = "verifier")]
    #[error("ECDSA signature error: {0}")]
    Ecdsa(#[from] p384::ecdsa::Error), // Changed to p384
    #[cfg(feature = "verifier")]
    #[error("Elliptic curve error: {0}")]
    EllipticCurve(#[from] p384::elliptic_curve::Error), // Changed to p384
    #[cfg(feature = "verifier")]
    #[error("X.509 certificate error: {0}")]
    X509(#[from] x509_cert::der::Error),
    #[error("TCB data is not valid")]
    Tcb,
    #[error("Measurement signature is not valid")]
    MeasurementSignature,
    #[error("IO error")]
    Io(#[from] std::io::Error),
    #[error("bincode error")]
    Bincode(#[from] Box<bincode::ErrorKind>),
    #[cfg(feature = "verifier")]
    #[error("Unsupported public key algorithm")]
    UnsupportedPublicKeyAlgorithm,
}

#[cfg(feature = "verifier")]
pub trait Validateable {
    fn validate(&self, vcek: &Vcek) -> Result<(), ValidateError>;
}

#[cfg(feature = "verifier")]
impl Validateable for AttestationReport {
    fn validate(&self, vcek: &Vcek) -> Result<(), ValidateError> {
        if !is_tcb_data_valid(self) {
            return Err(ValidateError::Tcb);
        }

        // Get attestation report signature - directly use try_from like your working implementation
        let signature = Signature::try_from(&self.signature)
            .map_err(|_| ValidateError::MeasurementSignature)?;

        // Extract the public key from the VCEK certificate
        let public_key_info = &vcek.0.tbs_certificate.subject_public_key_info;

        // Ensure this is an EC public key
        const EC_PUBLIC_KEY_OID: x509_cert::der::oid::ObjectIdentifier =
            x509_cert::der::oid::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

        if public_key_info.algorithm.oid != EC_PUBLIC_KEY_OID {
            return Err(ValidateError::UnsupportedPublicKeyAlgorithm);
        }

        // Parse the EC public key using P-384
        let public_key_bytes = public_key_info.subject_public_key.raw_bytes();
        let public_key = PublicKey::from_sec1_bytes(public_key_bytes)?;
        let verifying_key = VerifyingKey::from(&public_key);

        // Get the measurable bytes (first 0x2A0 bytes of serialized report)
        let base_message = get_report_base(self)?;

        // Create digest with prefix (like your working implementation)
        let digest = Sha384::new_with_prefix(&base_message);

        // Verify using digest verifier (not regular verifier!)
        if verifying_key.verify_digest(digest, &signature).is_err() {
            return Err(ValidateError::MeasurementSignature);
        }

        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum ReportError {
    #[error("deserialization error")]
    Parse(#[from] Box<bincode::ErrorKind>),
    #[error("vTPM error")]
    #[cfg(feature = "attester")]
    Vtpm(#[from] vtpm::ReportError),
    #[error("HCL error")]
    Hcl(#[from] hcl::HclError),
}

pub fn parse(bytes: &[u8]) -> Result<AttestationReport, ReportError> {
    // Use the sev's from_bytes method(since sev-6) which handles dynamic parsing
    // of different SNP report versions (v2, v3-PreTurin, v3-Turin)
    let snp_report = AttestationReport::from_bytes(bytes)
        .map_err(|e| ReportError::Parse(Box::new(bincode::ErrorKind::Io(e))))?;
    Ok(snp_report)
}

#[cfg(feature = "verifier")]
fn is_tcb_data_valid(report: &AttestationReport) -> bool {
    report.reported_tcb == report.committed_tcb
}

#[cfg(feature = "verifier")]
fn get_report_base(report: &AttestationReport) -> Result<Vec<u8>, Box<bincode::ErrorKind>> {
    // Use sev's write_bytes method (since SEV-6) for serializing SNP reports to ensure full compatibility
    // Original bincode::serialize + size_of calculation is inaccurate on SEV 6.x
    let mut raw_bytes = Vec::with_capacity(SNP_REPORT_SIZE);
    report
        .write_bytes(&mut raw_bytes)
        .map_err(|e| Box::new(bincode::ErrorKind::Io(e)))?;
    let report_bytes_without_sig = &raw_bytes[0..0x2a0];
    Ok(report_bytes_without_sig.to_vec())
}

/// Fetch TdReport from vTPM and parse it
#[cfg(feature = "attester")]
pub fn get_report() -> Result<AttestationReport, ReportError> {
    let bytes = vtpm::get_report()?;
    let hcl_report = HclReport::new(bytes)?;
    let snp_report = hcl_report.try_into()?;
    Ok(snp_report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hcl::HclReport;

    #[test]
    fn test_report_data_hash() {
        let bytes: &[u8] = include_bytes!("../../vtpm-attestation/test/hcl-report-snp.bin");
        let hcl_report = HclReport::new(bytes.to_vec()).unwrap();
        let var_data_hash = hcl_report.var_data_sha256();
        let snp_report: AttestationReport = hcl_report.try_into().unwrap();
        assert!(var_data_hash == snp_report.report_data[..32]);
    }
}
