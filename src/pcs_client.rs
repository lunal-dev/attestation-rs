use reqwest;
use serde_json::Value;
use std::error::Error;
use urlencoding::decode;

pub struct PcsClient {
    client: reqwest::Client,
    base_url: String,
}

pub struct TcbResponse {
    pub json_data: Value,
    pub issuer_chain_certs: Vec<String>,
}

impl TcbResponse {
    /// Convert JSON data to bytes for use with set_tcbinfo_bytes()
    pub fn json_to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&self.json_data)
    }

    /// Convert certificate strings to bytes
    pub fn certs_to_bytes(&self) -> Vec<Vec<u8>> {
        self.issuer_chain_certs
            .iter()
            .map(|cert| cert.as_bytes().to_vec())
            .collect()
    }
}

impl PcsClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: "https://api.trustedservices.intel.com/tdx/certification/v4".to_string(),
        }
    }

    /// Fetch QE (Quoting Enclave) identity information
    pub async fn get_qe_identity(&self) -> Result<Value, Box<dyn Error>> {
        let url = format!("{}/qe/identity", self.base_url);

        let response = self.client.get(&url).send().await?;

        if response.status().is_success() {
            let json: Value = response.json().await?;
            Ok(json)
        } else {
            Err(format!("HTTP error: {}", response.status()).into())
        }
    }

    /// Fetch TCB (Trusted Computing Base) information for a given FMSPC
    pub async fn get_tcb_info(&self, fmspc: &str) -> Result<TcbResponse, Box<dyn Error>> {
        let url = format!("{}/tcb?fmspc={}", self.base_url, fmspc);

        let response = self.client.get(&url).send().await?;

        if response.status().is_success() {
            let headers = response.headers().clone();
            let json: Value = response.json().await?;

            // Extract and process the TCB-Info-Issuer-Chain header
            let issuer_chain_certs =
                if let Some(chain_header) = headers.get("TCB-Info-Issuer-Chain") {
                    let chain_str = chain_header.to_str()?;
                    Self::parse_issuer_chain(chain_str)?
                } else {
                    Vec::new()
                };

            Ok(TcbResponse {
                json_data: json,
                issuer_chain_certs,
            })
        } else {
            Err(format!("HTTP error: {}", response.status()).into())
        }
    }

    /// Fetch PCK CRL (Platform Certification Key Certificate Revocation List)
    pub async fn get_pck_crl(&self, ca: &str, encoding: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        let url = format!(
            "https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca={}&encoding={}",
            ca, encoding
        );

        let response = self.client.get(&url).send().await?;

        if response.status().is_success() {
            let bytes = response.bytes().await?;
            Ok(bytes.to_vec())
        } else {
            Err(format!("HTTP error: {}", response.status()).into())
        }
    }

    fn parse_issuer_chain(chain_header: &str) -> Result<Vec<String>, Box<dyn Error>> {
        // URL decode the header value
        let decoded = decode(chain_header)?;

        // Replace URL-encoded newlines with actual newlines
        let normalized = decoded.replace("%0A", "\n");

        // Split on certificate boundaries and collect valid certificates
        let certificates: Vec<String> = normalized
            .split("-----BEGIN CERTIFICATE-----")
            .skip(1) // Skip the first empty part before the first certificate
            .filter_map(|part| {
                // Find where this certificate ends
                if let Some(end_pos) = part.find("-----END CERTIFICATE-----") {
                    let cert_body = &part[..end_pos];
                    Some(format!(
                        "-----BEGIN CERTIFICATE-----{}-----END CERTIFICATE-----",
                        cert_body
                    ))
                } else {
                    None
                }
            })
            .collect();

        Ok(certificates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_qe_identity() {
        let client = PcsClient::new();
        let data = client
            .get_qe_identity()
            .await
            .expect("Failed to fetch QE identity");

        // Assert on the structure/content you expect
        assert!(data.is_object());
        assert!(data.get("id").is_some()); // Example assertion
    }

    #[tokio::test]
    async fn test_tcb_info() {
        let client = PcsClient::new();
        let response = client
            .get_tcb_info("00806F050000")
            .await
            .expect("Failed to fetch TCB info");

        // Test the response structure
        assert!(response.json_data.is_object());
        assert!(!response.issuer_chain_certs.is_empty());

        // Test conversion methods work
        let json_bytes = response
            .json_to_bytes()
            .expect("Failed to convert JSON to bytes");
        assert!(!json_bytes.is_empty());

        let cert_bytes = response.certs_to_bytes();
        assert_eq!(cert_bytes.len(), response.issuer_chain_certs.len());
    }

    #[tokio::test]
    async fn test_pck_crl() {
        let client = PcsClient::new();
        let crl_data = client
            .get_pck_crl("platform", "der")
            .await
            .expect("Failed to fetch PCK CRL");

        // Assert the CRL data is not empty and has reasonable size
        assert!(!crl_data.is_empty());
        assert!(crl_data.len() > 100); // CRLs should be reasonably sized
    }
}
