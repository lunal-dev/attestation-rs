//! Map NRAS-issued EAT claims into our normalized [`NvidiaGpuClaims`] shape.

use crate::types::{NvidiaGpuArch, NvidiaGpuDeviceClaims};

/// Decode a single GPU submodule JWT body into [`NvidiaGpuDeviceClaims`].
///
/// Unknown / missing fields stay `None`. The full decoded JSON is retained in
/// `raw` so callers can inspect everything NRAS asserted.
pub fn device_claims_from_submodule(body: &serde_json::Value) -> NvidiaGpuDeviceClaims {
    let s = |k: &str| body.get(k).and_then(|v| v.as_str()).map(String::from);
    let b = |k: &str| body.get(k).and_then(|v| v.as_bool());

    NvidiaGpuDeviceClaims {
        arch: body
            .get("hwmodel")
            .and_then(|v| v.as_str())
            .and_then(arch_from_hwmodel),
        ueid: s("ueid"),
        hwmodel: s("hwmodel"),
        measres: s("measres"),
        secboot: b("secboot"),
        dbgstat: s("dbgstat"),
        driver_version: s("x-nvidia-gpu-driver-version"),
        vbios_version: s("x-nvidia-gpu-vbios-version"),
        arch_check: b("x-nvidia-gpu-arch-check"),
        nonce_match: b("x-nvidia-gpu-attestation-report-nonce-match"),
        report_signature_verified: b("x-nvidia-gpu-attestation-report-signature-verified"),
        driver_rim_fetched: b("x-nvidia-gpu-driver-rim-fetched"),
        vbios_rim_fetched: b("x-nvidia-gpu-vbios-rim-fetched"),
        raw: body.clone(),
    }
}

fn arch_from_hwmodel(s: &str) -> Option<NvidiaGpuArch> {
    let up = s.to_ascii_uppercase();
    if up.contains("HOPPER") || up.starts_with("GH100") {
        Some(NvidiaGpuArch::Hopper)
    } else if up.contains("BLACKWELL") || up.starts_with("GB") {
        Some(NvidiaGpuArch::Blackwell)
    } else if up.contains("LS10") || up.contains("SWITCH") {
        Some(NvidiaGpuArch::Ls10)
    } else {
        None
    }
}
