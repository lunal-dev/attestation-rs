//! Verify a [`NvidiaGpuEvidenceBundle`] using NRAS.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;

use crate::error::{AttestationError, Result};
use crate::platforms::nvidia_gpu::provider::{Jwks, NrasEvidenceEntry, NrasProvider, NrasRequest};
use crate::platforms::nvidia_gpu::{gpu_nonce, switch_nonce};
use crate::types::{
    NvidiaGpuArch, NvidiaGpuClaims, NvidiaGpuDeviceClaims, NvidiaGpuEvidenceBundle, VerifyParams,
};

/// Verify a GPU bundle end-to-end:
/// - Group devices by arch (NRAS requires one arch per request).
/// - Derive the SPDM nonce from `params.nvidia_gpu_user_nonce` per `bundle.binding`.
/// - POST evidence to NRAS, JWS-verify the response, check `eat_nonce` and
///   `x-nvidia-overall-att-result`.
///
/// Returns aggregated [`NvidiaGpuClaims`]. Caller is responsible for asserting any
/// `claims.platform_data` ↔ `claims.gpu` semantic coupling (e.g. the same
/// `user_nonce` was used).
pub async fn verify_bundle(
    bundle: &NvidiaGpuEvidenceBundle,
    params: &VerifyParams,
    provider: &dyn NrasProvider,
) -> Result<NvidiaGpuClaims> {
    let user_nonce = check_preconditions(bundle, params)?;

    let mut aggregated = NvidiaGpuClaims {
        overall_ok: true,
        eat_nonce: None,
        nonce_binding_ok: true,
        devices: Vec::with_capacity(bundle.devices.len()),
        overall_raw: serde_json::Value::Null,
    };

    for (arch, devices) in group_by_arch(bundle) {
        let group = verify_arch_group(arch, &devices, user_nonce, bundle, provider).await?;
        fold_arch_group(&mut aggregated, group);
    }

    final_checks(&aggregated, bundle.devices.len())?;
    log::info!(
        "NVIDIA GPU attestation passed: {} device(s), nonce_binding_ok=true",
        aggregated.devices.len()
    );
    Ok(aggregated)
}

const MAX_GPU_DEVICES: usize = 32;

/// Validate bundle and params before any network or crypto work. Returns the
/// validated `user_nonce` slice on success.
fn check_preconditions<'a>(
    bundle: &NvidiaGpuEvidenceBundle,
    params: &'a VerifyParams,
) -> Result<&'a [u8]> {
    if bundle.devices.is_empty() {
        return Err(AttestationError::NvidiaGpuBundleEmpty);
    }
    if bundle.devices.len() > MAX_GPU_DEVICES {
        return Err(AttestationError::NvidiaGpuTooManyDevices(
            bundle.devices.len(),
            MAX_GPU_DEVICES,
        ));
    }
    let user_nonce = params
        .nvidia_gpu_user_nonce
        .as_deref()
        .ok_or(AttestationError::NvidiaGpuUserNonceMissing)?;
    super::check_user_nonce_len(user_nonce)?;

    // Enforce allowed binding algorithms. Default: only Concat { Sha256 }.
    let default_allowed = [crate::types::NvidiaGpuBinding::default()];
    let allowed = params
        .nvidia_gpu_allowed_bindings
        .as_deref()
        .unwrap_or(&default_allowed);
    if !allowed.contains(&bundle.binding) {
        return Err(AttestationError::NvidiaGpuBindingNotAllowed);
    }

    if let Some(whitelist) = &params.nvidia_gpu_expected_archs {
        for dev in &bundle.devices {
            if !whitelist.contains(&dev.arch) {
                return Err(AttestationError::NvidiaGpuArchNotAllowed(
                    dev.arch.to_string(),
                ));
            }
        }
    }

    Ok(user_nonce)
}

/// NRAS requires one request per arch. Group the bundle accordingly.
fn group_by_arch(
    bundle: &NvidiaGpuEvidenceBundle,
) -> std::collections::BTreeMap<NvidiaGpuArch, Vec<&crate::types::NvidiaGpuDeviceEvidence>> {
    let mut by_arch: std::collections::BTreeMap<
        NvidiaGpuArch,
        Vec<&crate::types::NvidiaGpuDeviceEvidence>,
    > = Default::default();
    for dev in &bundle.devices {
        by_arch.entry(dev.arch).or_default().push(dev);
    }
    by_arch
}

/// Result of attesting + verifying one arch group. The caller folds these
/// into the running [`NvidiaGpuClaims`] aggregate.
struct ArchGroupResult {
    overall_ok: bool,
    eat_nonce: Option<String>,
    nonce_binding_ok: bool,
    overall_raw: serde_json::Value,
    devices: Vec<crate::types::NvidiaGpuDeviceClaims>,
}

/// Build the NRAS request, attest, JWS-verify the overall + each submodule,
/// and check the eat_nonce binding against the derived SPDM nonce.
async fn verify_arch_group(
    arch: NvidiaGpuArch,
    devices: &[&crate::types::NvidiaGpuDeviceEvidence],
    user_nonce: &[u8],
    bundle: &NvidiaGpuEvidenceBundle,
    provider: &dyn NrasProvider,
) -> Result<ArchGroupResult> {
    let nonce_bytes = match arch {
        NvidiaGpuArch::Ls10 => switch_nonce(user_nonce, &bundle.binding),
        _ => gpu_nonce(user_nonce, &bundle.binding),
    };
    let nonce_hex = hex::encode(nonce_bytes);

    let request = NrasRequest {
        nonce: nonce_hex.clone(),
        evidence_list: devices
            .iter()
            .map(|d| NrasEvidenceEntry {
                evidence: d.evidence_b64.clone(),
                certificate: d.cert_chain_b64.clone(),
            })
            .collect(),
        arch,
        claims_version: "2.0".into(),
    };

    let response = provider.attest(&request).await?;
    let (overall_jwt, submodule_jwts) = split_eat_response(&response)?;
    let mut jwks = provider.jwks(arch).await?;

    let overall_claims =
        verify_jws_with_kid_rotation(&overall_jwt, &mut jwks, arch, provider).await?;
    let overall_ok = overall_claims
        .get("x-nvidia-overall-att-result")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let eat_nonce = overall_claims
        .get("eat_nonce")
        .and_then(|v| v.as_str())
        .map(String::from);
    let nonce_binding_ok = eat_nonce
        .as_deref()
        .and_then(|n| hex::decode(n).ok())
        .map(|decoded| {
            use subtle::ConstantTimeEq;
            decoded.ct_eq(&nonce_bytes).into()
        })
        .unwrap_or(false);

    let mut device_claims = Vec::with_capacity(submodule_jwts.len());
    for (_name, sub_jwt) in submodule_jwts {
        let sub_claims = verify_jws_with_kid_rotation(&sub_jwt, &mut jwks, arch, provider).await?;
        let mut dc = device_claims_from_submodule(&sub_claims);
        if dc.arch.is_none() {
            dc.arch = Some(arch);
        }
        device_claims.push(dc);
    }

    Ok(ArchGroupResult {
        overall_ok,
        eat_nonce,
        nonce_binding_ok,
        overall_raw: overall_claims,
        devices: device_claims,
    })
}

/// Merge a per-arch result into the running aggregate. `overall_raw` overwrites
/// each iteration — fine for v1, where multiple arches in one bundle is rare.
fn fold_arch_group(aggregated: &mut NvidiaGpuClaims, group: ArchGroupResult) {
    aggregated.overall_ok &= group.overall_ok;
    aggregated.nonce_binding_ok &= group.nonce_binding_ok;
    if aggregated.eat_nonce.is_none() {
        aggregated.eat_nonce = group.eat_nonce;
    }
    aggregated.overall_raw = group.overall_raw;
    aggregated.devices.extend(group.devices);
}

/// Post-aggregation invariants: every device produced claims, overall passed,
/// and the eat_nonce bound to our derived SPDM nonce.
fn final_checks(aggregated: &NvidiaGpuClaims, expected_devices: usize) -> Result<()> {
    if aggregated.devices.len() != expected_devices {
        log::warn!(
            "NVIDIA GPU attestation: device count mismatch (expected {}, got {})",
            expected_devices,
            aggregated.devices.len()
        );
        return Err(AttestationError::NvidiaGpuDeviceCountMismatch {
            expected: expected_devices,
            got: aggregated.devices.len(),
        });
    }
    if !aggregated.overall_ok {
        log::warn!("NVIDIA GPU attestation: NRAS overall result is false");
        return Err(AttestationError::NrasOverallFailed);
    }
    if !aggregated.nonce_binding_ok {
        log::warn!("NVIDIA GPU attestation: nonce binding mismatch");
        return Err(AttestationError::NvidiaGpuBindingMismatch);
    }
    Ok(())
}

/// Verify a JWS, transparently refetching the JWKS once on `kid` miss.
///
/// NRAS rotates signing keys without coordination. Both the overall and
/// per-submodule JWTs in a single response may reference a kid that wasn't
/// in our cached JWKS at the time of fetch. On miss, force-refresh once and
/// retry. After the refetch, `*jwks` reflects the new key set so subsequent
/// calls (e.g. for submodule JWTs after the overall has rotated) use the
/// refreshed material without an extra round-trip.
async fn verify_jws_with_kid_rotation(
    token: &str,
    jwks: &mut Jwks,
    arch: NvidiaGpuArch,
    provider: &dyn NrasProvider,
) -> Result<serde_json::Value> {
    match verify_jws_es384(token, jwks) {
        Err(AttestationError::JwksKidNotFound(_)) => {
            *jwks = provider.jwks_force(arch).await?;
            verify_jws_es384(token, jwks)
        }
        other => other,
    }
}

/// NRAS returns either a single JWT string or a 2-tuple "detached EAT" of
/// the shape `[ ["JWT", "<overall>"], { "<name>": "<jwt>", ... } ]`.
fn split_eat_response(v: &serde_json::Value) -> Result<(String, Vec<(String, String)>)> {
    if let Some(s) = v.as_str() {
        return Ok((s.to_string(), vec![]));
    }
    if let Some(arr) = v.as_array() {
        if arr.len() == 2 {
            let inner = arr[0].as_array().ok_or_else(|| {
                AttestationError::NrasResponseParse("EAT[0] is not an array".into())
            })?;
            if inner.first().and_then(|v| v.as_str()) != Some("JWT") {
                return Err(AttestationError::NrasResponseParse(
                    "EAT[0][0] is not \"JWT\"".into(),
                ));
            }
            let overall = inner
                .get(1)
                .and_then(|j| j.as_str())
                .ok_or_else(|| {
                    AttestationError::NrasResponseParse("missing overall JWT in EAT".into())
                })?
                .to_string();
            let mut subs = Vec::new();
            if let Some(map) = arr[1].as_object() {
                for (k, val) in map {
                    if let Some(s) = val.as_str() {
                        subs.push((k.clone(), s.to_string()));
                    }
                }
            }
            return Ok((overall, subs));
        }
    }
    let preview = {
        let s = v.to_string();
        if s.len() > 512 {
            let mut end = 512;
            while !s.is_char_boundary(end) {
                end -= 1;
            }
            format!("{}...", &s[..end])
        } else {
            s
        }
    };
    Err(AttestationError::NrasResponseParse(format!(
        "unexpected NRAS response shape: {preview}"
    )))
}

/// Verify an ES384-signed compact JWS against a JWKS, returning the decoded
/// claims body.
pub fn verify_jws_es384(token: &str, jwks: &Jwks) -> Result<serde_json::Value> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AttestationError::JwsVerification(
            "not a compact JWS".into(),
        ));
    }
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| AttestationError::JwsVerification(format!("header b64: {e}")))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| AttestationError::JwsVerification(format!("header json: {e}")))?;
    let alg = header.get("alg").and_then(|v| v.as_str()).unwrap_or("");
    if alg != "ES384" {
        return Err(AttestationError::JwsVerification(format!(
            "unsupported alg {alg}"
        )));
    }
    let kid = header
        .get("kid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AttestationError::JwsVerification("missing kid".into()))?;
    let key = jwks
        .keys
        .iter()
        .find(|k| k.kid == kid)
        .ok_or_else(|| AttestationError::JwksKidNotFound(kid.to_string()))?;

    let verifying_key = es384_verifying_key_from_jwks_entry(key)?;

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|e| AttestationError::JwsVerification(format!("sig b64: {e}")))?;
    let signature = p384::ecdsa::Signature::from_slice(&sig_bytes)
        .map_err(|e| AttestationError::JwsVerification(format!("ES384 sig parse: {e}")))?;
    {
        use p384::ecdsa::signature::Verifier as _;
        verifying_key
            .verify(signing_input.as_bytes(), &signature)
            .map_err(|e| AttestationError::JwsVerification(format!("ES384 verify: {e}")))?;
    }

    let payload = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| AttestationError::JwsVerification(format!("payload b64: {e}")))?;
    let claims: serde_json::Value = serde_json::from_slice(&payload)
        .map_err(|e| AttestationError::JwsVerification(format!("payload json: {e}")))?;

    // Enforce `exp` on all targets, including wasm32. `chrono::Utc::now()` is a
    // non-optional dependency and works on wasm, so we avoid `SystemTime` (which
    // we previously cfg'd out, silently accepting expired EATs in the browser).
    if let Some(exp) = claims.get("exp").and_then(|v| v.as_i64()) {
        let now = chrono::Utc::now().timestamp();
        if now > exp {
            return Err(AttestationError::JwsVerification(
                "JWT has expired (exp)".into(),
            ));
        }
    }

    Ok(claims)
}

fn es384_verifying_key_from_jwks_entry(
    key: &crate::platforms::nvidia_gpu::provider::JwksKey,
) -> Result<p384::ecdsa::VerifyingKey> {
    // Prefer the x5c chain (NRAS publishes one); fall back to JWK ec coords.
    if let Some(chain) = &key.x5c {
        if !chain.is_empty() {
            return verify_x5c_chain_and_extract_key(chain);
        }
    }
    if let (Some(x_b64), Some(y_b64)) = (&key.x, &key.y) {
        let x = URL_SAFE_NO_PAD
            .decode(x_b64.as_bytes())
            .map_err(|e| AttestationError::JwsVerification(format!("jwk x b64: {e}")))?;
        let y = URL_SAFE_NO_PAD
            .decode(y_b64.as_bytes())
            .map_err(|e| AttestationError::JwsVerification(format!("jwk y b64: {e}")))?;
        if x.len() != 48 || y.len() != 48 {
            return Err(AttestationError::JwsVerification(
                "jwk ec coords wrong length for P-384".into(),
            ));
        }
        let mut sec1 = Vec::with_capacity(1 + 96);
        sec1.push(0x04);
        sec1.extend_from_slice(&x);
        sec1.extend_from_slice(&y);
        return p384::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
            .map_err(|e| AttestationError::JwsVerification(format!("ES384 sec1: {e}")));
    }
    Err(AttestationError::JwsVerification(
        "JWKS entry has neither x5c nor (x,y)".into(),
    ))
}

/// SHA-256 hashes of trusted NRAS intermediate CA Subject Public Key Info (SPKI).
/// The topmost certificate in the x5c chain must have an SPKI matching one of these.
///
/// GPU/Switch Intermediate 004 — valid 2025-12-08 to 2029-12-08
/// Subject: CN=NVIDIA Attestation Service GPU Intermediate 004
/// Issuer:  CN=NVIDIA Attestation Service CA 001
const NRAS_TRUSTED_SPKI_SHA256: &[&str] =
    &["fd32837f954e2c45db073105166dfe6985ae0480bb113fba63b091a75affe896"];

/// Validate the x5c certificate chain and return the leaf's P-384 verifying key.
///
/// Checks: each cert is signed by the next in the chain (EC or RSA), all
/// certs are within their validity period, and the topmost cert's SPKI
/// matches a pinned NVIDIA trust anchor.
fn verify_x5c_chain_and_extract_key(chain: &[String]) -> Result<p384::ecdsa::VerifyingKey> {
    use sha2::Digest;
    use spki::DecodePublicKey;
    use x509_cert::der::Decode;

    if chain.is_empty() {
        return Err(AttestationError::JwsVerification(
            "x5c chain is empty".into(),
        ));
    }

    let certs: Vec<(Vec<u8>, x509_cert::Certificate)> = chain
        .iter()
        .enumerate()
        .map(|(i, b64)| {
            let der = STANDARD
                .decode(b64.as_bytes())
                .map_err(|e| AttestationError::JwsVerification(format!("x5c[{i}] b64: {e}")))?;
            let cert = x509_cert::Certificate::from_der(&der).map_err(|e| {
                AttestationError::JwsVerification(format!("x5c[{i}] cert parse: {e}"))
            })?;
            Ok((der, cert))
        })
        .collect::<Result<Vec<_>>>()?;

    // Enforce certificate validity periods on all targets, including wasm32.
    // `chrono::Utc::now()` works on wasm (unlike `SystemTime`, which we used to
    // cfg out — silently accepting expired NRAS signing certs in the browser).
    {
        let now_secs = chrono::Utc::now().timestamp();
        for (i, (_der, cert)) in certs.iter().enumerate() {
            let validity = &cert.tbs_certificate.validity;
            let nb_unix: i64 = validity
                .not_before
                .to_date_time()
                .unix_duration()
                .as_secs()
                .try_into()
                .map_err(|_| {
                    AttestationError::JwsVerification(format!("x5c[{i}] not_before overflow"))
                })?;
            if now_secs < nb_unix {
                return Err(AttestationError::JwsVerification(format!(
                    "x5c[{i}] certificate not yet valid"
                )));
            }
            let na_unix: i64 = validity
                .not_after
                .to_date_time()
                .unix_duration()
                .as_secs()
                .try_into()
                .map_err(|_| {
                    AttestationError::JwsVerification(format!("x5c[{i}] not_after overflow"))
                })?;
            if now_secs > na_unix {
                return Err(AttestationError::JwsVerification(format!(
                    "x5c[{i}] certificate has expired"
                )));
            }
        }
    }

    // Verify chain signatures: cert[i] must be signed by cert[i+1].
    for i in 0..certs.len().saturating_sub(1) {
        verify_cert_signature(&certs[i].1, &certs[i + 1].1, i)?;
    }

    // Pin the topmost cert against trusted SPKI hashes instead of requiring
    // self-signature (the NRAS intermediate is signed by an offline root CA
    // that is not included in the x5c chain).
    let top = &certs[certs.len() - 1].1;
    let top_spki_der = spki::der::Encode::to_der(&top.tbs_certificate.subject_public_key_info)
        .map_err(|e| AttestationError::JwsVerification(format!("x5c top spki encode: {e}")))?;
    let top_spki_hash = hex::encode(sha2::Sha256::digest(&top_spki_der));
    if !NRAS_TRUSTED_SPKI_SHA256.contains(&top_spki_hash.as_str()) {
        return Err(AttestationError::JwsVerification(format!(
            "x5c chain root SPKI not in trusted set (got {top_spki_hash})"
        )));
    }

    // Extract leaf public key.
    let leaf_spki = &certs[0].1.tbs_certificate.subject_public_key_info;
    let leaf_spki_der = spki::der::Encode::to_der(leaf_spki)
        .map_err(|e| AttestationError::JwsVerification(format!("x5c leaf spki encode: {e}")))?;
    p384::ecdsa::VerifyingKey::from_public_key_der(&leaf_spki_der)
        .map_err(|e| AttestationError::JwsVerification(format!("x5c leaf ES384 key: {e}")))
}

/// Verify that `cert` was signed by `issuer`, dispatching on the certificate's
/// `signatureAlgorithm` OID. Supports the algorithms NRAS uses today:
/// ECDSA with SHA-256/SHA-384 and RSA PKCS#1 v1.5 with SHA-256/SHA-384.
fn verify_cert_signature(
    cert: &x509_cert::Certificate,
    issuer: &x509_cert::Certificate,
    index: usize,
) -> Result<()> {
    use der::oid::db::rfc5912::{
        ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, SHA_256_WITH_RSA_ENCRYPTION,
        SHA_384_WITH_RSA_ENCRYPTION,
    };

    let issuer_spki_der = spki::der::Encode::to_der(
        &issuer.tbs_certificate.subject_public_key_info,
    )
    .map_err(|e| AttestationError::JwsVerification(format!("x5c issuer spki encode: {e}")))?;
    let tbs_der = spki::der::Encode::to_der(&cert.tbs_certificate)
        .map_err(|e| AttestationError::JwsVerification(format!("x5c[{index}] tbs encode: {e}")))?;
    let sig_bytes = cert.signature.raw_bytes();
    let sig_alg = cert.signature_algorithm.oid;

    let verified = match sig_alg {
        ECDSA_WITH_SHA_384 => verify_ecdsa_p384(&issuer_spki_der, &tbs_der, sig_bytes),
        ECDSA_WITH_SHA_256 => verify_ecdsa_p256(&issuer_spki_der, &tbs_der, sig_bytes),
        SHA_256_WITH_RSA_ENCRYPTION => verify_rsa_sha256(&issuer_spki_der, &tbs_der, sig_bytes),
        SHA_384_WITH_RSA_ENCRYPTION => verify_rsa_sha384(&issuer_spki_der, &tbs_der, sig_bytes),
        other => {
            return Err(AttestationError::JwsVerification(format!(
                "x5c[{index}] unsupported signatureAlgorithm: {other}"
            )));
        }
    };
    if verified {
        Ok(())
    } else {
        Err(AttestationError::JwsVerification(format!(
            "x5c[{index}] not signed by x5c[{}]",
            index + 1
        )))
    }
}

fn verify_ecdsa_p384(issuer_spki: &[u8], tbs: &[u8], sig_bytes: &[u8]) -> bool {
    use p384::ecdsa::signature::Verifier as _;
    use spki::DecodePublicKey as _;
    let Ok(key) = p384::ecdsa::VerifyingKey::from_public_key_der(issuer_spki) else {
        return false;
    };
    let Ok(sig) = p384::ecdsa::DerSignature::from_bytes(sig_bytes) else {
        return false;
    };
    key.verify(tbs, &sig).is_ok()
}

fn verify_ecdsa_p256(issuer_spki: &[u8], tbs: &[u8], sig_bytes: &[u8]) -> bool {
    use p256::ecdsa::signature::Verifier as _;
    use spki::DecodePublicKey as _;
    let Ok(key) = p256::ecdsa::VerifyingKey::from_public_key_der(issuer_spki) else {
        return false;
    };
    let Ok(sig) = p256::ecdsa::DerSignature::from_bytes(sig_bytes) else {
        return false;
    };
    key.verify(tbs, &sig).is_ok()
}

fn verify_rsa_sha256(issuer_spki: &[u8], tbs: &[u8], sig_bytes: &[u8]) -> bool {
    use signature::Verifier as _;
    use spki::DecodePublicKey as _;
    let Ok(key) = rsa::RsaPublicKey::from_public_key_der(issuer_spki) else {
        return false;
    };
    let verifier = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(key);
    let Ok(sig) = rsa::pkcs1v15::Signature::try_from(sig_bytes) else {
        return false;
    };
    verifier.verify(tbs, &sig).is_ok()
}

fn verify_rsa_sha384(issuer_spki: &[u8], tbs: &[u8], sig_bytes: &[u8]) -> bool {
    use signature::Verifier as _;
    use spki::DecodePublicKey as _;
    let Ok(key) = rsa::RsaPublicKey::from_public_key_der(issuer_spki) else {
        return false;
    };
    let verifier = rsa::pkcs1v15::VerifyingKey::<sha2::Sha384>::new(key);
    let Ok(sig) = rsa::pkcs1v15::Signature::try_from(sig_bytes) else {
        return false;
    };
    verifier.verify(tbs, &sig).is_ok()
}

/// Decode a single GPU submodule JWT body into [`NvidiaGpuDeviceClaims`].
fn device_claims_from_submodule(body: &serde_json::Value) -> NvidiaGpuDeviceClaims {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platforms::nvidia_gpu::MIN_GPU_USER_NONCE_LEN;
    use crate::types::{
        NvidiaGpuArch, NvidiaGpuBinding, NvidiaGpuDeviceEvidence, NvidiaGpuEvidenceBundle,
        VerifyParams,
    };

    /// `NrasProvider` whose methods panic on call. Used to prove `verify_bundle`
    /// short-circuits on bad input before reaching the network/FFI.
    struct PanicProvider;

    #[async_trait::async_trait]
    impl NrasProvider for PanicProvider {
        fn url_for(&self, _arch: NvidiaGpuArch) -> &str {
            "https://invalid.test/should-not-be-called"
        }
        async fn attest(&self, _request: &NrasRequest) -> Result<serde_json::Value> {
            panic!("verify_bundle reached provider.attest() with invalid input");
        }
        async fn jwks(&self, _arch: NvidiaGpuArch) -> Result<Jwks> {
            panic!("verify_bundle reached provider.jwks() with invalid input");
        }
    }

    fn one_device_bundle() -> NvidiaGpuEvidenceBundle {
        NvidiaGpuEvidenceBundle {
            devices: vec![NvidiaGpuDeviceEvidence {
                arch: NvidiaGpuArch::Blackwell,
                uuid: "GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into(),
                evidence_b64: String::new(),
                cert_chain_b64: String::new(),
            }],
            binding: NvidiaGpuBinding::default(),
        }
    }

    /// Real bug this catches: removing the `check_user_nonce_len(user_nonce)?`
    /// call site from `verify_bundle` (verify.rs:40). The helper would
    /// still exist, the unit-level branch would still work, but a short nonce
    /// would silently flow into the NRAS request. The `PanicProvider` exists
    /// to assert the rejection happens *before* any network call.
    #[tokio::test]
    async fn verify_bundle_rejects_short_user_nonce_before_provider_call() {
        let too_short = vec![0u8; MIN_GPU_USER_NONCE_LEN - 1];
        let bundle = one_device_bundle();
        let params = VerifyParams {
            nvidia_gpu_user_nonce: Some(too_short.clone()),
            ..Default::default()
        };

        let result = verify_bundle(&bundle, &params, &PanicProvider).await;

        match result {
            Err(AttestationError::NvidiaGpuNonceTooShort(n)) => {
                assert_eq!(n, too_short.len());
            }
            other => panic!("expected NvidiaGpuNonceTooShort, got {other:?}"),
        }
    }
}
