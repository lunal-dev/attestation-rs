use thiserror::Error;

/// Unified error type for all attestation operations.
#[derive(Error, Debug)]
pub enum AttestationError {
    #[error("no supported TEE platform detected")]
    NoPlatformDetected,

    #[error("platform {0} is not enabled (missing feature flag)")]
    PlatformNotEnabled(String),

    #[error("report_data exceeds maximum size ({max} bytes)")]
    ReportDataTooLarge { max: usize },

    #[error("evidence deserialization failed: {0}")]
    EvidenceDeserialize(String),

    #[error("hardware signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    #[error("certificate chain validation failed: {0}")]
    CertChainError(String),

    #[error("certificate fetch failed: {0}")]
    CertFetchError(String),

    #[error("quote parsing failed: {0}")]
    QuoteParseFailed(String),

    #[error("report version {version} not supported (min: {min}, max: {max})")]
    UnsupportedReportVersion { version: u32, min: u32, max: u32 },

    #[error("VMPL check failed: expected 0, got {0}")]
    VmplCheckFailed(u32),

    #[error("eventlog integrity check failed: {0}")]
    EventlogIntegrityFailed(String),

    #[error("TEE hardware access failed: {0}")]
    HardwareAccessFailed(String),

    #[error("TCB version mismatch: {0}")]
    TcbMismatch(String),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, AttestationError>;
