//! GPU nonce derivation from a user nonce.
//!
//! NRAS accepts one nonce per request shared across every device in the
//! batch, so the v1 binding does not enumerate per-device UUIDs.

use sha2::{Digest, Sha256};

use crate::types::{NvidiaGpuBinding, NvidiaGpuHashAlgo};

const GPU_DOMAIN_TAG: &[u8] = b"NVIDIA-GPU-EAT-v1";
const SWITCH_DOMAIN_TAG: &[u8] = b"NVIDIA-SWITCH-EAT-v1";

/// Derive the SPDM nonce used to challenge GPUs in a batch.
///
/// `binding` selects the algorithm; v1 only supports `Concat { Sha256 }`.
pub fn gpu_nonce(user_nonce: &[u8], binding: &NvidiaGpuBinding) -> [u8; 32] {
    derive(user_nonce, GPU_DOMAIN_TAG, binding)
}

/// Derive the SPDM nonce used to challenge NVSwitches in a batch.
pub fn switch_nonce(user_nonce: &[u8], binding: &NvidiaGpuBinding) -> [u8; 32] {
    derive(user_nonce, SWITCH_DOMAIN_TAG, binding)
}

fn derive(user_nonce: &[u8], domain_tag: &[u8], binding: &NvidiaGpuBinding) -> [u8; 32] {
    match binding {
        NvidiaGpuBinding::Concat { algo } => match algo {
            NvidiaGpuHashAlgo::Sha256 => {
                let mut h = Sha256::new();
                h.update(user_nonce);
                h.update(domain_tag);
                h.finalize().into()
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gpu_nonce_is_deterministic() {
        let user = b"test-nonce";
        let b = NvidiaGpuBinding::default();
        assert_eq!(gpu_nonce(user, &b), gpu_nonce(user, &b));
    }

    #[test]
    fn gpu_and_switch_nonces_are_domain_separated() {
        let user = b"x";
        let b = NvidiaGpuBinding::default();
        assert_ne!(gpu_nonce(user, &b), switch_nonce(user, &b));
    }

    #[test]
    fn distinct_user_nonces_yield_distinct_gpu_nonces() {
        let b = NvidiaGpuBinding::default();
        assert_ne!(gpu_nonce(b"a", &b), gpu_nonce(b"b", &b));
    }
}
