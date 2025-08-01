#[cfg(feature = "legacy")]
use crate::coco::snp::snp_error::{FirmwareError, VmmError};
use std::{array::TryFromSliceError, fmt::Display, num::ParseIntError, string::FromUtf8Error};

pub type Result<T> = std::result::Result<T, CocoError>;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum CocoError {
    Firmware(String),
    IO(String),
    Permission(String),
    Tpm(String),
    Unknown,
}

impl Display for CocoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CocoError::Firmware(msg) => write!(f, "Firmware: {}", msg),
            CocoError::IO(msg) => write!(f, "IO: {}", msg),
            CocoError::Permission(msg) => write!(f, "Permission: {}", msg),
            CocoError::Tpm(msg) => write!(f, "TPM: {}", msg),
            CocoError::Unknown => write!(f, "Unknown"),
        }
    }
}

impl std::error::Error for CocoError {}

impl From<std::io::Error> for CocoError {
    fn from(err: std::io::Error) -> Self {
        CocoError::Firmware(format!("{err:?}"))
    }
}

#[cfg(all(feature = "tpm", target_os = "linux"))]
impl From<tss_esapi::Error> for CocoError {
    fn from(err: tss_esapi::Error) -> Self {
        CocoError::Tpm(format!("{err}"))
    }
}

impl From<FromUtf8Error> for CocoError {
    fn from(err: FromUtf8Error) -> Self {
        CocoError::IO(format!("{err:?}"))
    }
}

impl From<TryFromSliceError> for CocoError {
    fn from(err: TryFromSliceError) -> Self {
        CocoError::IO(format!("{err:?}"))
    }
}

impl From<ParseIntError> for CocoError {
    fn from(err: ParseIntError) -> Self {
        CocoError::IO(format!("{err:?}"))
    }
}

#[cfg(feature = "tpm")]
impl From<Box<bincode::ErrorKind>> for CocoError {
    fn from(err: Box<bincode::ErrorKind>) -> Self {
        CocoError::IO(format!("{err:?}"))
    }
}

impl From<uuid::Error> for CocoError {
    fn from(err: uuid::Error) -> Self {
        CocoError::IO(format!("{err:?}"))
    }
}

#[cfg(feature = "legacy")]
impl From<FirmwareError> for CocoError {
    fn from(err: crate::coco::snp::snp_error::FirmwareError) -> Self {
        CocoError::Firmware(format!("{err}"))
    }
}

#[cfg(feature = "legacy")]
impl From<VmmError> for CocoError {
    fn from(err: crate::coco::snp::snp_error::VmmError) -> Self {
        CocoError::Firmware(format!("{err}"))
    }
}
