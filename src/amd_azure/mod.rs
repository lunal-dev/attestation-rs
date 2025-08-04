#[cfg(feature = "attestation")]
pub mod attest;

pub mod verify;

#[cfg(target_arch = "wasm32")]
pub mod wasm;

use az_snp_vtpm::{imds, quote};
use serde::{Deserialize, Serialize};
use std::error::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationEvidence {
    pub report: Vec<u8>,
    pub quote: quote::Quote,
    pub certs: imds::Certificates,
    pub report_data: Vec<u8>,
}

impl AttestationEvidence {
    /// Serialize to bytes using bincode
    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(bincode::serialize(self)?)
    }

    /// Deserialize from bytes using bincode
    pub fn from_bytes(data: &[u8]) -> Result<Self, Box<dyn Error>> {
        Ok(bincode::deserialize(data)?)
    }
}
