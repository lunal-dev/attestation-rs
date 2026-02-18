use async_trait::async_trait;

use crate::error::Result;
use crate::types::{ProcessorGeneration, SnpTcb};

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
            client: reqwest::Client::new(),
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
    fn vcek_url(
        processor_gen: ProcessorGeneration,
        chip_id: &[u8; 64],
        tcb: &SnpTcb,
    ) -> String {
        let chip_id_hex = hex::encode(chip_id);
        format!(
            "https://kdsintf.amd.com/vcek/v1/{}/{}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
            processor_gen.product_name(),
            chip_id_hex,
            tcb.bootloader,
            tcb.tee,
            tcb.snp,
            tcb.microcode,
        )
    }

    /// Build AMD KDS URL for cert chain (ARK + ASK).
    fn cert_chain_url(processor_gen: ProcessorGeneration) -> String {
        format!(
            "https://kdsintf.amd.com/vcek/v1/{}/cert_chain",
            processor_gen.product_name()
        )
    }
}

impl Default for DefaultCertProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CertProvider for DefaultCertProvider {
    async fn get_snp_vcek(
        &self,
        processor_gen: ProcessorGeneration,
        chip_id: &[u8; 64],
        reported_tcb: &SnpTcb,
    ) -> Result<Vec<u8>> {
        let url = Self::vcek_url(processor_gen, chip_id, reported_tcb);

        // Check cache
        if let Some(cached) = self.get_cached(&url) {
            return Ok(cached);
        }

        // Fetch from AMD KDS
        #[cfg(not(target_arch = "wasm32"))]
        {
            let response = self
                .client
                .get(&url)
                .send()
                .await
                .map_err(|e| crate::error::AttestationError::CertFetchError(e.to_string()))?;

            if !response.status().is_success() {
                return Err(crate::error::AttestationError::CertFetchError(format!(
                    "AMD KDS returned status {}",
                    response.status()
                )));
            }

            let data = response
                .bytes()
                .await
                .map_err(|e| crate::error::AttestationError::CertFetchError(e.to_string()))?
                .to_vec();

            self.set_cached(url, data.clone());
            Ok(data)
        }

        #[cfg(target_arch = "wasm32")]
        {
            Err(crate::error::AttestationError::CertFetchError(
                "WASM cert fetching not yet implemented".to_string(),
            ))
        }
    }

    async fn get_snp_cert_chain(
        &self,
        processor_gen: ProcessorGeneration,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        // For now, return the bundled certs
        #[cfg(feature = "snp")]
        {
            let (ark, ask) =
                crate::platforms::snp::certs::get_bundled_certs(processor_gen);
            Ok((ark.to_vec(), ask.to_vec()))
        }

        #[cfg(not(feature = "snp"))]
        {
            let _ = processor_gen;
            Err(crate::error::AttestationError::PlatformNotEnabled(
                "snp".to_string(),
            ))
        }
    }
}
