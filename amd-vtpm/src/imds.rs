
use crate::HttpError;
use serde::{Deserialize, Serialize};
use serde_json;

const IMDS_CERT_URL: &str = "http://169.254.169.254/metadata/THIM/amd/certification";

/// PEM encoded VCEK certificate and AMD certificate chain.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Certificates {
    #[serde(rename = "vcekCert")]
    pub vcek: String,
    #[serde(rename = "certificateChain")]
    pub amd_chain: String,
}

impl Certificates {
    /// Convert the certificates to a JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Convert the certificates to pretty-printed JSON string
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// Get the VCEK certificate and the certificate chain from the Azure IMDS.
/// **Note:** this can only be called from a Confidential VM.
pub async fn get_certs() -> Result<Certificates, HttpError> {
    let client = reqwest::Client::new();
    let res: Certificates = client
        .get(IMDS_CERT_URL)
        .header("Metadata", "true")
        .send()
        .await?
        .json()
        .await?;
    Ok(res)
}
