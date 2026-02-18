use async_trait::async_trait;
#[cfg(not(target_arch = "wasm32"))]
use base64::Engine;

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
        let bytes = self
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
            })?
            .bytes()
            .await
            .map_err(|e| {
                crate::error::AttestationError::CertFetchError(format!("read body: {}", e))
            })?
            .to_vec();

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
        // Use bundled certs
        #[cfg(feature = "snp")]
        {
            let (ark, ask) = crate::platforms::snp::certs::get_bundled_certs(processor_gen);
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

impl Default for DefaultCertProvider {
    fn default() -> Self {
        Self::new()
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
        };
        let url = DefaultCertProvider::vcek_url(ProcessorGeneration::Milan, &chip_id, &tcb);

        assert!(url.starts_with("https://kdsintf.amd.com/vcek/v1/Milan/"));
        assert!(url.contains(&hex::encode(chip_id)));
        assert!(url.contains("blSPL=03"));
        assert!(url.contains("teeSPL=00"));
        assert!(url.contains("snpSPL=08"));
        assert!(url.contains("ucodeSPL=115"));
    }

    #[test]
    fn test_vcek_url_construction_genoa() {
        let chip_id = [0xBB; 64];
        let tcb = SnpTcb {
            bootloader: 1,
            tee: 2,
            snp: 3,
            microcode: 4,
        };
        let url = DefaultCertProvider::vcek_url(ProcessorGeneration::Genoa, &chip_id, &tcb);

        assert!(url.starts_with("https://kdsintf.amd.com/vcek/v1/Genoa/"));
        assert!(url.contains(&hex::encode(chip_id)));
        assert!(url.contains("blSPL=01"));
        assert!(url.contains("teeSPL=02"));
        assert!(url.contains("snpSPL=03"));
        assert!(url.contains("ucodeSPL=04"));
    }

    #[test]
    fn test_vcek_url_construction_turin() {
        let chip_id = [0xCC; 64];
        let tcb = SnpTcb {
            bootloader: 0,
            tee: 0,
            snp: 0,
            microcode: 0,
        };
        let url = DefaultCertProvider::vcek_url(ProcessorGeneration::Turin, &chip_id, &tcb);

        assert!(url.starts_with("https://kdsintf.amd.com/vcek/v1/Turin/"));
        assert!(url.contains(&hex::encode(chip_id)));
        assert!(url.contains("blSPL=00"));
        assert!(url.contains("teeSPL=00"));
        assert!(url.contains("snpSPL=00"));
        assert!(url.contains("ucodeSPL=00"));
    }

    #[test]
    fn test_vcek_url_contains_all_tcb_params() {
        let chip_id = [0x00; 64];
        let tcb = SnpTcb {
            bootloader: 255,
            tee: 128,
            snp: 64,
            microcode: 32,
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
}
