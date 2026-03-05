use std::time::Duration;

use async_trait::async_trait;
#[cfg(not(target_arch = "wasm32"))]
use base64::Engine;

use crate::error::Result;
use crate::types::{ProcessorGeneration, SnpTcb};

/// HTTP request timeout (total).
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// HTTP connection timeout.
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum allowed HTTP response body size (5 MiB).
const MAX_RESPONSE_SIZE: usize = 5 * 1024 * 1024;

/// Trait for providing platform vendor certificates.
/// The library ships a default impl that does HTTP fetch with in-memory caching.
/// Users can plug in their own (Redis, disk, etc.).
#[async_trait]
pub trait CertProvider: Send + Sync {
    /// Fetch the VCEK/VLEK cert for an SNP report.
    async fn get_snp_vcek(
        &self,
        processor_gen: ProcessorGeneration,
        chip_id: &[u8; 64],
        reported_tcb: &SnpTcb,
    ) -> Result<Vec<u8>>;

    /// Fetch the AMD certificate chain (ARK + ASK) for a processor generation.
    async fn get_snp_cert_chain(
        &self,
        processor_gen: ProcessorGeneration,
    ) -> Result<(Vec<u8>, Vec<u8>)>;
}

/// Default implementation: try cache first, fetch from vendor on miss.
pub struct DefaultCertProvider {
    #[cfg(not(target_arch = "wasm32"))]
    client: reqwest::Client,
    cache: std::sync::Arc<std::sync::RwLock<std::collections::HashMap<String, CachedCert>>>,
}

#[derive(Clone)]
struct CachedCert {
    data: Vec<u8>,
    fetched_at: std::time::Instant,
}

impl CachedCert {
    fn is_expired(&self, ttl: std::time::Duration) -> bool {
        self.fetched_at.elapsed() > ttl
    }
}

const CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(3600); // 1 hour

impl DefaultCertProvider {
    pub fn new() -> Self {
        Self {
            #[cfg(not(target_arch = "wasm32"))]
            client: reqwest::Client::builder()
                .timeout(HTTP_TIMEOUT)
                .connect_timeout(HTTP_CONNECT_TIMEOUT)
                .build()
                .expect("failed to build HTTP client"),
            cache: std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        }
    }

    fn get_cached(&self, key: &str) -> Option<Vec<u8>> {
        let cache = self.cache.read().ok()?;
        let entry = cache.get(key)?;
        if entry.is_expired(CACHE_TTL) {
            None
        } else {
            Some(entry.data.clone())
        }
    }

    #[allow(dead_code)] // Only used in native (non-WASM) builds
    fn set_cached(&self, key: String, data: Vec<u8>) {
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(
                key,
                CachedCert {
                    data,
                    fetched_at: std::time::Instant::now(),
                },
            );
        }
    }

    /// Build AMD KDS URL for VCEK certificate.
    fn vcek_url(processor_gen: ProcessorGeneration, chip_id: &[u8; 64], tcb: &SnpTcb) -> String {
        // Turin uses only the first 8 bytes of chip_id for KDS lookup
        let chip_id_hex = if processor_gen == ProcessorGeneration::Turin {
            hex::encode(&chip_id[..8])
        } else {
            hex::encode(chip_id)
        };
        let mut url = format!(
            "https://kdsintf.amd.com/vcek/v1/{}/{}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
            processor_gen.product_name(),
            chip_id_hex,
            tcb.bootloader,
            tcb.tee,
            tcb.snp,
            tcb.microcode,
        );
        // Turin processors have an additional FMC SPL parameter
        if let Some(fmc) = tcb.fmc {
            url.push_str(&format!("&fmcSPL={:02}", fmc));
        }
        url
    }

    /// Build AMD KDS URL for cert chain (ARK + ASK).
    pub fn cert_chain_url(processor_gen: ProcessorGeneration) -> String {
        format!(
            "https://kdsintf.amd.com/vcek/v1/{}/cert_chain",
            processor_gen.product_name()
        )
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl DefaultCertProvider {
    /// Fetch a certificate from AMD KDS, with cache lookup first.
    async fn fetch_cert(&self, url: &str) -> Result<Vec<u8>> {
        // Try cache first
        if let Some(cached) = self.get_cached(url) {
            return Ok(cached);
        }

        // Fetch from network
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| {
                crate::error::AttestationError::CertFetchError(format!("HTTP request: {}", e))
            })?
            .error_for_status()
            .map_err(|e| {
                crate::error::AttestationError::CertFetchError(format!("HTTP status: {}", e))
            })?;

        // Check Content-Length header before reading body
        if let Some(len) = response.content_length() {
            if len as usize > MAX_RESPONSE_SIZE {
                return Err(crate::error::AttestationError::CertFetchError(format!(
                    "response too large: Content-Length {} exceeds {} byte limit",
                    len, MAX_RESPONSE_SIZE
                )));
            }
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| {
                crate::error::AttestationError::CertFetchError(format!("read body: {}", e))
            })?
            .to_vec();

        if bytes.len() > MAX_RESPONSE_SIZE {
            return Err(crate::error::AttestationError::CertFetchError(format!(
                "response body too large: {} bytes exceeds {} byte limit",
                bytes.len(),
                MAX_RESPONSE_SIZE
            )));
        }

        // Cache the result
        self.set_cached(url.to_string(), bytes.clone());

        Ok(bytes)
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
impl CertProvider for DefaultCertProvider {
    async fn get_snp_vcek(
        &self,
        processor_gen: ProcessorGeneration,
        chip_id: &[u8; 64],
        reported_tcb: &SnpTcb,
    ) -> Result<Vec<u8>> {
        let url = Self::vcek_url(processor_gen, chip_id, reported_tcb);
        self.fetch_cert(&url).await
    }

    async fn get_snp_cert_chain(
        &self,
        processor_gen: ProcessorGeneration,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let url = Self::cert_chain_url(processor_gen);
        let pem_data = self.fetch_cert(&url).await?;

        // The cert chain response is PEM with two certificates (ARK + ASK)
        // Parse them into DER
        let pem_str = String::from_utf8(pem_data).map_err(|e| {
            crate::error::AttestationError::CertFetchError(format!("cert chain not UTF-8: {}", e))
        })?;

        let mut certs = Vec::new();
        let mut current = String::new();
        let mut in_cert = false;

        for line in pem_str.lines() {
            if line.contains("BEGIN CERTIFICATE") {
                in_cert = true;
                current.clear();
            } else if line.contains("END CERTIFICATE") {
                in_cert = false;
                let der = base64::engine::general_purpose::STANDARD
                    .decode(current.trim())
                    .map_err(|e| {
                        crate::error::AttestationError::CertFetchError(format!(
                            "cert base64: {}",
                            e
                        ))
                    })?;
                certs.push(der);
            } else if in_cert {
                current.push_str(line.trim());
            }
        }

        if certs.len() < 2 {
            return Err(crate::error::AttestationError::CertFetchError(format!(
                "expected 2 certs in chain, got {}",
                certs.len()
            )));
        }

        // First cert is typically VCEK/ASK, second is ARK
        // The AMD KDS returns ASK first, ARK second
        Ok((certs[1].clone(), certs[0].clone()))
    }
}

/// WASM implementation: uses bundled certs for chain, no HTTP fetch for VCEK.
/// In a browser environment, callers should provide their own CertProvider
/// implementation that uses fetch() or similar for VCEK resolution.
#[cfg(target_arch = "wasm32")]
#[async_trait]
impl CertProvider for DefaultCertProvider {
    async fn get_snp_vcek(
        &self,
        processor_gen: ProcessorGeneration,
        chip_id: &[u8; 64],
        reported_tcb: &SnpTcb,
    ) -> Result<Vec<u8>> {
        // Check cache first
        let url = Self::vcek_url(processor_gen, chip_id, reported_tcb);
        if let Some(cached) = self.get_cached(&url) {
            return Ok(cached);
        }

        Err(crate::error::AttestationError::CertFetchError(
            "VCEK fetch requires a custom CertProvider implementation in WASM".to_string(),
        ))
    }

    async fn get_snp_cert_chain(
        &self,
        processor_gen: ProcessorGeneration,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let (ark, ask) = crate::platforms::snp::certs::get_bundled_certs(processor_gen);
        Ok((ark.to_vec(), ask.to_vec()))
    }
}

impl Default for DefaultCertProvider {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// TDX DCAP collateral provider (Intel PCS v4)
// ---------------------------------------------------------------------------

/// Trait for fetching Intel TDX DCAP collateral (TCB Info, QE Identity, CRLs).
///
/// The library ships a default impl that fetches from Intel PCS v4.
/// Users can plug in their own (offline bundles, caching proxies, etc.).
#[async_trait]
pub trait TdxCollateralProvider: Send + Sync {
    /// Fetch TDX TCB Info JSON for a given FMSPC.
    async fn get_tcb_info(&self, fmspc: &str) -> Result<Vec<u8>>;

    /// Fetch the QE Identity JSON.
    async fn get_qe_identity(&self) -> Result<Vec<u8>>;

    /// Fetch the Intel SGX Root CA CRL (DER-encoded).
    async fn get_root_ca_crl(&self) -> Result<Vec<u8>>;

    /// Fetch the PCK CRL for a given CA type ("platform" or "processor").
    async fn get_pck_crl(&self, ca: &str) -> Result<Vec<u8>>;

    /// Fetch the TCB Info signing certificate chain (PEM).
    ///
    /// This is the `TCB-Info-Issuer-Chain` response header from Intel PCS,
    /// containing the Intel SGX TCB Signing Certificate → Root CA chain.
    /// Used to verify the Intel ECDSA signature on TCB Info JSON.
    ///
    /// Returns `None` if the signing chain is not available (signature
    /// verification will be skipped).
    async fn get_tcb_signing_chain(&self) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }

    /// Fetch the QE Identity signing certificate chain (PEM).
    ///
    /// This is the `SGX-Enclave-Identity-Issuer-Chain` response header from
    /// Intel PCS. Used to verify the Intel ECDSA signature on QE Identity JSON.
    ///
    /// Returns `None` if the signing chain is not available (signature
    /// verification will be skipped).
    async fn get_qe_identity_signing_chain(&self) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
}

/// Default TDX collateral provider: fetches from Intel PCS v4 with caching.
pub struct DefaultTdxCollateralProvider {
    #[cfg(not(target_arch = "wasm32"))]
    client: reqwest::Client,
    cache: std::sync::Arc<std::sync::RwLock<std::collections::HashMap<String, CachedCert>>>,
}

impl DefaultTdxCollateralProvider {
    pub fn new() -> Self {
        Self {
            #[cfg(not(target_arch = "wasm32"))]
            client: reqwest::Client::builder()
                .timeout(HTTP_TIMEOUT)
                .connect_timeout(HTTP_CONNECT_TIMEOUT)
                .build()
                .expect("failed to build HTTP client"),
            cache: std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        }
    }

    fn get_cached(&self, key: &str) -> Option<Vec<u8>> {
        let cache = self.cache.read().ok()?;
        let entry = cache.get(key)?;
        if entry.is_expired(CACHE_TTL) {
            None
        } else {
            Some(entry.data.clone())
        }
    }

    #[allow(dead_code)]
    fn set_cached(&self, key: String, data: Vec<u8>) {
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(
                key,
                CachedCert {
                    data,
                    fetched_at: std::time::Instant::now(),
                },
            );
        }
    }

    /// Intel PCS v4 TDX TCB Info URL.
    pub fn tcb_info_url(fmspc: &str) -> String {
        format!(
            "https://api.trustedservices.intel.com/sgx/certification/v4/tcb?fmspc={}",
            fmspc
        )
    }

    /// Intel PCS v4 QE Identity URL.
    pub fn qe_identity_url() -> String {
        "https://api.trustedservices.intel.com/sgx/certification/v4/qe/identity".to_string()
    }

    /// Intel SGX Root CA CRL URL (DER format).
    pub fn root_ca_crl_url() -> String {
        "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der".to_string()
    }

    /// Intel PCS v4 PCK CRL URL.
    pub fn pck_crl_url(ca: &str) -> String {
        format!(
            "https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca={}",
            ca
        )
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl DefaultTdxCollateralProvider {
    async fn fetch(&self, url: &str) -> Result<Vec<u8>> {
        if let Some(cached) = self.get_cached(url) {
            return Ok(cached);
        }

        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| {
                crate::error::AttestationError::CertFetchError(format!("HTTP request: {}", e))
            })?
            .error_for_status()
            .map_err(|e| {
                crate::error::AttestationError::CertFetchError(format!("HTTP status: {}", e))
            })?;

        if let Some(len) = response.content_length() {
            if len as usize > MAX_RESPONSE_SIZE {
                return Err(crate::error::AttestationError::CertFetchError(format!(
                    "response too large: Content-Length {} exceeds {} byte limit",
                    len, MAX_RESPONSE_SIZE
                )));
            }
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| {
                crate::error::AttestationError::CertFetchError(format!("read body: {}", e))
            })?
            .to_vec();

        if bytes.len() > MAX_RESPONSE_SIZE {
            return Err(crate::error::AttestationError::CertFetchError(format!(
                "response body too large: {} bytes exceeds {} byte limit",
                bytes.len(),
                MAX_RESPONSE_SIZE
            )));
        }

        self.set_cached(url.to_string(), bytes.clone());
        Ok(bytes)
    }

    /// Fetch a URL and capture a specific response header as PEM cert chain.
    ///
    /// Intel PCS returns signing cert chains as URL-encoded PEM in response
    /// headers (`TCB-Info-Issuer-Chain`, `SGX-Enclave-Identity-Issuer-Chain`).
    async fn fetch_with_signing_chain(
        &self,
        url: &str,
        header_name: &str,
        chain_cache_key: &str,
    ) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
        // Check body cache
        if let Some(cached_body) = self.get_cached(url) {
            let chain = self.get_cached(chain_cache_key);
            return Ok((cached_body, chain));
        }

        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| {
                crate::error::AttestationError::CertFetchError(format!("HTTP request: {}", e))
            })?
            .error_for_status()
            .map_err(|e| {
                crate::error::AttestationError::CertFetchError(format!("HTTP status: {}", e))
            })?;

        if let Some(len) = response.content_length() {
            if len as usize > MAX_RESPONSE_SIZE {
                return Err(crate::error::AttestationError::CertFetchError(format!(
                    "response too large: Content-Length {} exceeds {} byte limit",
                    len, MAX_RESPONSE_SIZE
                )));
            }
        }

        // Extract signing chain from response header (URL-encoded PEM)
        let chain_pem = response
            .headers()
            .get(header_name)
            .and_then(|v| v.to_str().ok())
            .map(|v| percent_decode(v).into_bytes());

        let body = response
            .bytes()
            .await
            .map_err(|e| {
                crate::error::AttestationError::CertFetchError(format!("read body: {}", e))
            })?
            .to_vec();

        if body.len() > MAX_RESPONSE_SIZE {
            return Err(crate::error::AttestationError::CertFetchError(format!(
                "response body too large: {} bytes exceeds {} byte limit",
                body.len(),
                MAX_RESPONSE_SIZE
            )));
        }

        self.set_cached(url.to_string(), body.clone());
        if let Some(ref chain) = chain_pem {
            self.set_cached(chain_cache_key.to_string(), chain.clone());
        }

        Ok((body, chain_pem))
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
impl TdxCollateralProvider for DefaultTdxCollateralProvider {
    async fn get_tcb_info(&self, fmspc: &str) -> Result<Vec<u8>> {
        let url = Self::tcb_info_url(fmspc);
        let (body, chain) = self
            .fetch_with_signing_chain(&url, "tcb-info-issuer-chain", "tcb_signing_chain")
            .await?;
        if let Some(ref chain_pem) = chain {
            self.set_cached("tcb_signing_chain".to_string(), chain_pem.clone());
        }
        Ok(body)
    }

    async fn get_qe_identity(&self) -> Result<Vec<u8>> {
        let url = Self::qe_identity_url();
        let (body, chain) = self
            .fetch_with_signing_chain(
                &url,
                "sgx-enclave-identity-issuer-chain",
                "qe_identity_signing_chain",
            )
            .await?;
        if let Some(ref chain_pem) = chain {
            self.set_cached("qe_identity_signing_chain".to_string(), chain_pem.clone());
        }
        Ok(body)
    }

    async fn get_root_ca_crl(&self) -> Result<Vec<u8>> {
        self.fetch(&Self::root_ca_crl_url()).await
    }

    async fn get_pck_crl(&self, ca: &str) -> Result<Vec<u8>> {
        self.fetch(&Self::pck_crl_url(ca)).await
    }

    async fn get_tcb_signing_chain(&self) -> Result<Option<Vec<u8>>> {
        Ok(self.get_cached("tcb_signing_chain"))
    }

    async fn get_qe_identity_signing_chain(&self) -> Result<Option<Vec<u8>>> {
        Ok(self.get_cached("qe_identity_signing_chain"))
    }
}

#[cfg(target_arch = "wasm32")]
#[async_trait]
impl TdxCollateralProvider for DefaultTdxCollateralProvider {
    async fn get_tcb_info(&self, fmspc: &str) -> Result<Vec<u8>> {
        let url = Self::tcb_info_url(fmspc);
        if let Some(cached) = self.get_cached(&url) {
            return Ok(cached);
        }
        Err(crate::error::AttestationError::CertFetchError(
            "TDX collateral fetch requires a custom TdxCollateralProvider in WASM".to_string(),
        ))
    }

    async fn get_qe_identity(&self) -> Result<Vec<u8>> {
        let url = Self::qe_identity_url();
        if let Some(cached) = self.get_cached(&url) {
            return Ok(cached);
        }
        Err(crate::error::AttestationError::CertFetchError(
            "TDX collateral fetch requires a custom TdxCollateralProvider in WASM".to_string(),
        ))
    }

    async fn get_root_ca_crl(&self) -> Result<Vec<u8>> {
        let url = Self::root_ca_crl_url();
        if let Some(cached) = self.get_cached(&url) {
            return Ok(cached);
        }
        Err(crate::error::AttestationError::CertFetchError(
            "TDX collateral fetch requires a custom TdxCollateralProvider in WASM".to_string(),
        ))
    }

    async fn get_pck_crl(&self, ca: &str) -> Result<Vec<u8>> {
        let url = Self::pck_crl_url(ca);
        if let Some(cached) = self.get_cached(&url) {
            return Ok(cached);
        }
        Err(crate::error::AttestationError::CertFetchError(
            "TDX collateral fetch requires a custom TdxCollateralProvider in WASM".to_string(),
        ))
    }
}

impl Default for DefaultTdxCollateralProvider {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple percent-decoding for URL-encoded PEM strings from Intel PCS headers.
#[cfg(not(target_arch = "wasm32"))]
fn percent_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            if let (Some(h), Some(l)) = (chars.next(), chars.next()) {
                if let (Some(hv), Some(lv)) = (hex_val(h), hex_val(l)) {
                    result.push((hv << 4 | lv) as char);
                    continue;
                }
            }
            result.push('%');
        } else if b == b'+' {
            result.push(' ');
        } else {
            result.push(b as char);
        }
    }
    result
}

#[cfg(not(target_arch = "wasm32"))]
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vcek_url_construction_milan() {
        let chip_id = [0xAA; 64];
        let tcb = SnpTcb {
            bootloader: 3,
            tee: 0,
            snp: 8,
            microcode: 115,
            fmc: None,
        };
        let url = DefaultCertProvider::vcek_url(ProcessorGeneration::Milan, &chip_id, &tcb);

        assert!(url.starts_with("https://kdsintf.amd.com/vcek/v1/Milan/"));
        assert!(url.contains(&hex::encode(chip_id)));
        assert!(url.contains("blSPL=03"));
        assert!(url.contains("teeSPL=00"));
        assert!(url.contains("snpSPL=08"));
        assert!(url.contains("ucodeSPL=115"));
        assert!(!url.contains("fmcSPL"), "Milan should not include fmcSPL");
    }

    #[test]
    fn test_vcek_url_construction_genoa() {
        let chip_id = [0xBB; 64];
        let tcb = SnpTcb {
            bootloader: 1,
            tee: 2,
            snp: 3,
            microcode: 4,
            fmc: None,
        };
        let url = DefaultCertProvider::vcek_url(ProcessorGeneration::Genoa, &chip_id, &tcb);

        assert!(url.starts_with("https://kdsintf.amd.com/vcek/v1/Genoa/"));
        assert!(url.contains(&hex::encode(chip_id)));
        assert!(url.contains("blSPL=01"));
        assert!(url.contains("teeSPL=02"));
        assert!(url.contains("snpSPL=03"));
        assert!(url.contains("ucodeSPL=04"));
        assert!(!url.contains("fmcSPL"), "Genoa should not include fmcSPL");
    }

    #[test]
    fn test_vcek_url_construction_turin() {
        let chip_id = [0xCC; 64];
        let tcb = SnpTcb {
            bootloader: 0,
            tee: 0,
            snp: 0,
            microcode: 0,
            fmc: Some(10),
        };
        let url = DefaultCertProvider::vcek_url(ProcessorGeneration::Turin, &chip_id, &tcb);

        assert!(url.starts_with("https://kdsintf.amd.com/vcek/v1/Turin/"));
        // Turin uses only first 8 bytes of chip_id
        assert!(url.contains(&hex::encode(&chip_id[..8])));
        assert!(
            !url.contains(&hex::encode(chip_id)),
            "Turin should NOT use full 64-byte chip_id"
        );
        assert!(url.contains("blSPL=00"));
        assert!(url.contains("teeSPL=00"));
        assert!(url.contains("snpSPL=00"));
        assert!(url.contains("ucodeSPL=00"));
        assert!(url.contains("fmcSPL=10"), "Turin should include fmcSPL");
    }

    #[test]
    fn test_vcek_url_contains_all_tcb_params() {
        let chip_id = [0x00; 64];
        let tcb = SnpTcb {
            bootloader: 255,
            tee: 128,
            snp: 64,
            microcode: 32,
            fmc: None,
        };
        let url = DefaultCertProvider::vcek_url(ProcessorGeneration::Milan, &chip_id, &tcb);

        // URL should contain all 4 TCB query parameters
        assert!(url.contains("blSPL="), "missing blSPL param");
        assert!(url.contains("teeSPL="), "missing teeSPL param");
        assert!(url.contains("snpSPL="), "missing snpSPL param");
        assert!(url.contains("ucodeSPL="), "missing ucodeSPL param");
    }

    #[test]
    fn test_cert_chain_url_construction() {
        let url = DefaultCertProvider::cert_chain_url(ProcessorGeneration::Milan);
        assert_eq!(url, "https://kdsintf.amd.com/vcek/v1/Milan/cert_chain");

        let url = DefaultCertProvider::cert_chain_url(ProcessorGeneration::Genoa);
        assert_eq!(url, "https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain");

        let url = DefaultCertProvider::cert_chain_url(ProcessorGeneration::Turin);
        assert_eq!(url, "https://kdsintf.amd.com/vcek/v1/Turin/cert_chain");
    }

    #[test]
    fn test_cache_operations() {
        let provider = DefaultCertProvider::new();

        // Cache should be empty initially
        assert!(provider.get_cached("test-key").is_none());

        // Set a value
        provider.set_cached("test-key".to_string(), vec![1, 2, 3]);

        // Should retrieve the value
        let cached = provider.get_cached("test-key");
        assert!(cached.is_some());
        assert_eq!(cached.unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn test_cache_different_keys() {
        let provider = DefaultCertProvider::new();

        provider.set_cached("key-a".to_string(), vec![10, 20]);
        provider.set_cached("key-b".to_string(), vec![30, 40]);

        assert_eq!(provider.get_cached("key-a").unwrap(), vec![10, 20]);
        assert_eq!(provider.get_cached("key-b").unwrap(), vec![30, 40]);
        assert!(provider.get_cached("key-c").is_none());
    }

    #[test]
    fn test_cache_overwrite() {
        let provider = DefaultCertProvider::new();

        provider.set_cached("key".to_string(), vec![1, 2, 3]);
        assert_eq!(provider.get_cached("key").unwrap(), vec![1, 2, 3]);

        // Overwrite with new value
        provider.set_cached("key".to_string(), vec![4, 5, 6]);
        assert_eq!(provider.get_cached("key").unwrap(), vec![4, 5, 6]);
    }

    #[test]
    fn test_cache_empty_value() {
        let provider = DefaultCertProvider::new();

        provider.set_cached("empty".to_string(), vec![]);
        let cached = provider.get_cached("empty");
        assert!(cached.is_some());
        assert!(cached.unwrap().is_empty());
    }

    #[test]
    fn test_cached_cert_is_expired() {
        let cert = CachedCert {
            data: vec![1, 2, 3],
            fetched_at: std::time::Instant::now(),
        };

        // Should not be expired with a 1-hour TTL
        assert!(!cert.is_expired(std::time::Duration::from_secs(3600)));

        // Should be expired with a zero TTL
        assert!(cert.is_expired(std::time::Duration::from_secs(0)));
    }

    #[test]
    fn test_default_cert_provider_creation() {
        // Ensure we can create a DefaultCertProvider via new() and Default
        let p1 = DefaultCertProvider::new();
        let p2 = DefaultCertProvider::default();

        // Both should have empty caches
        assert!(p1.get_cached("nonexistent").is_none());
        assert!(p2.get_cached("nonexistent").is_none());
    }

    // --- TDX collateral provider tests ---

    #[test]
    fn test_tdx_tcb_info_url() {
        let url = DefaultTdxCollateralProvider::tcb_info_url("00906ED50000");
        assert_eq!(
            url,
            "https://api.trustedservices.intel.com/sgx/certification/v4/tcb?fmspc=00906ED50000"
        );
    }

    #[test]
    fn test_tdx_qe_identity_url() {
        let url = DefaultTdxCollateralProvider::qe_identity_url();
        assert_eq!(
            url,
            "https://api.trustedservices.intel.com/sgx/certification/v4/qe/identity"
        );
    }

    #[test]
    fn test_tdx_root_ca_crl_url() {
        let url = DefaultTdxCollateralProvider::root_ca_crl_url();
        assert_eq!(
            url,
            "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"
        );
    }

    #[test]
    fn test_tdx_pck_crl_url() {
        let url = DefaultTdxCollateralProvider::pck_crl_url("platform");
        assert_eq!(
            url,
            "https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform"
        );

        let url = DefaultTdxCollateralProvider::pck_crl_url("processor");
        assert_eq!(
            url,
            "https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=processor"
        );
    }

    #[test]
    fn test_tdx_collateral_provider_creation() {
        let p1 = DefaultTdxCollateralProvider::new();
        let p2 = DefaultTdxCollateralProvider::default();

        assert!(p1.get_cached("nonexistent").is_none());
        assert!(p2.get_cached("nonexistent").is_none());
    }

    #[test]
    fn test_tdx_collateral_provider_cache() {
        let provider = DefaultTdxCollateralProvider::new();

        provider.set_cached("tcb-info".to_string(), vec![1, 2, 3]);
        assert_eq!(provider.get_cached("tcb-info").unwrap(), vec![1, 2, 3]);

        // Different key should miss
        assert!(provider.get_cached("other").is_none());
    }
}
