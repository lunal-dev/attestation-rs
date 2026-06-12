//! GPU evidence collection on a CC-mode Linux host (attester side).
//!
//! Uses NVIDIA's official Rust attestation SDK (`nv-attestation-sdk`) to
//! collect SPDM evidence from CC-enabled GPUs (NVML) and NVSwitches (NSCQ).
//!
//! See `README.md` for the C++ SDK build prereq this feature pulls in.

use std::sync::OnceLock;

use nv_attestation_sdk::{GpuEvidenceSource, Nonce, NvatSdk, SdkOptions, SwitchEvidenceSource};
use serde::Deserialize;

use crate::error::{AttestationError, Result};
use crate::platforms::nvidia_gpu::{gpu_nonce, switch_nonce};
use crate::types::{
    NvidiaGpuArch, NvidiaGpuBinding, NvidiaGpuDeviceEvidence, NvidiaGpuEvidenceBundle,
};

/// The NVAT SDK must be initialized exactly once and the handle kept alive
/// for the lifetime of all subsequent calls. We initialize lazily, leak the
/// handle, and stash the (success-or-error) result so callers can re-check
/// without re-initializing.
static SDK_INIT: OnceLock<std::result::Result<(), String>> = OnceLock::new();

fn ensure_sdk_init() -> Result<()> {
    SDK_INIT
        .get_or_init(|| -> std::result::Result<(), String> {
            let opts = SdkOptions::new().map_err(|e| format!("SdkOptions::new: {e}"))?;
            let sdk = NvatSdk::init(opts).map_err(|e| format!("NvatSdk::init: {e}"))?;
            // SDK handle must outlive every call — leak it on purpose.
            std::mem::forget(sdk);
            Ok(())
        })
        .as_ref()
        .map_err(|e| {
            AttestationError::NvidiaGpuEvidenceCollection(format!("NVAT SDK init: {e}"))
        })?;
    Ok(())
}

/// Wire shape of one entry as the NVIDIA SDK serializes it via `to_json()`.
/// Matches the NRAS request body field names; we re-map into our envelope.
#[derive(Deserialize)]
struct SdkEvidenceEntry {
    arch: String,
    #[serde(default)]
    uuid: Option<String>,
    evidence: String,
    certificate: String,
}

/// Collect GPU + switch SPDM evidence on the local host.
///
/// The SPDM nonce passed to GPUs is `gpu_nonce(user_nonce, binding)`; the
/// nonce passed to NVSwitches is `switch_nonce(user_nonce, binding)`. Both
/// are deterministic from the caller's `user_nonce` so the verifier can
/// rederive them and confirm NRAS attested to the same values.
pub async fn collect_bundle(
    user_nonce: &[u8],
    binding: NvidiaGpuBinding,
) -> Result<NvidiaGpuEvidenceBundle> {
    // SDK calls are blocking; hand them to a blocking-pool worker so the
    // current async runtime stays responsive.
    let user_nonce = user_nonce.to_vec();
    tokio::task::spawn_blocking(move || collect_blocking(&user_nonce, binding))
        .await
        .map_err(|e| {
            AttestationError::NvidiaGpuEvidenceCollection(format!("spawn_blocking: {e}"))
        })?
}

fn collect_blocking(
    user_nonce: &[u8],
    binding: NvidiaGpuBinding,
) -> Result<NvidiaGpuEvidenceBundle> {
    ensure_sdk_init()?;

    let gpu_n_bytes = gpu_nonce(user_nonce, &binding);
    let switch_n_bytes = switch_nonce(user_nonce, &binding);
    let gpu_n = Nonce::from_hex(&hex::encode(gpu_n_bytes))
        .map_err(|e| AttestationError::NvidiaGpuEvidenceCollection(format!("Nonce gpu: {e}")))?;
    let switch_n = Nonce::from_hex(&hex::encode(switch_n_bytes))
        .map_err(|e| AttestationError::NvidiaGpuEvidenceCollection(format!("Nonce switch: {e}")))?;

    let mut entries: Vec<SdkEvidenceEntry> = Vec::new();

    // Per-source failures (constructor or .collect()) mean "this device
    // class isn't present here" — log and move on. The assertion at the
    // bottom guarantees we collected *something*. Only a JSON-decode error
    // from the SDK output is fatal.
    if let Ok(src) = GpuEvidenceSource::from_nvml() {
        match src.collect(&gpu_n) {
            Ok(ev) if !ev.is_empty() => {
                let json = ev.to_json().map_err(|e| {
                    AttestationError::NvidiaGpuEvidenceCollection(format!("gpu to_json: {e}"))
                })?;
                let mut got: Vec<SdkEvidenceEntry> = serde_json::from_str(&json).map_err(|e| {
                    AttestationError::NvidiaGpuEvidenceCollection(format!("parse gpu json: {e}"))
                })?;
                entries.append(&mut got);
            }
            Ok(_) => log::debug!("no CC GPU evidence collected"),
            Err(e) => log::warn!("GPU evidence collect failed (continuing): {e}"),
        }
    } else {
        log::debug!("GpuEvidenceSource::from_nvml unavailable (no GPU?)");
    }

    if let Ok(src) = SwitchEvidenceSource::from_nscq() {
        match src.collect(&switch_n) {
            Ok(ev) if !ev.is_empty() => {
                let json = ev.to_json().map_err(|e| {
                    AttestationError::NvidiaGpuEvidenceCollection(format!("switch to_json: {e}"))
                })?;
                let mut got: Vec<SdkEvidenceEntry> = serde_json::from_str(&json).map_err(|e| {
                    AttestationError::NvidiaGpuEvidenceCollection(format!("parse switch json: {e}"))
                })?;
                entries.append(&mut got);
            }
            Ok(_) => log::debug!("no NVSwitch evidence collected"),
            Err(e) => log::warn!("switch evidence collect failed (continuing): {e}"),
        }
    } else {
        log::debug!("SwitchEvidenceSource::from_nscq unavailable (no switches?)");
    }

    if entries.is_empty() {
        return Err(AttestationError::NvidiaGpuEvidenceCollection(
            "no CC GPUs or switches reported by NVAT SDK".into(),
        ));
    }

    let mut devices: Vec<NvidiaGpuDeviceEvidence> = entries
        .into_iter()
        .map(|e| {
            let arch = match e.arch.to_ascii_uppercase().as_str() {
                "HOPPER" => NvidiaGpuArch::Hopper,
                "BLACKWELL" => NvidiaGpuArch::Blackwell,
                "LS10" => NvidiaGpuArch::Ls10,
                other => {
                    return Err(AttestationError::NvidiaGpuEvidenceCollection(format!(
                        "unknown arch from SDK: {other}"
                    )));
                }
            };
            Ok(NvidiaGpuDeviceEvidence {
                arch,
                uuid: e.uuid.unwrap_or_else(|| "unknown".into()),
                evidence_b64: e.evidence,
                cert_chain_b64: e.certificate,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    devices.sort_by(|a, b| a.uuid.cmp(&b.uuid));
    Ok(NvidiaGpuEvidenceBundle { devices, binding })
}
