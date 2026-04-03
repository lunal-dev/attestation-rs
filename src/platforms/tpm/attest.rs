use std::str::FromStr;

use crate::error::{AttestationError, Result};
use crate::platforms::tpm_common::TpmQuote;

use super::evidence::TpmEvidence;

const TPM_DEVICE_PATH: &str = "/dev/tpmrm0";
const TPM_SYSFS_PATH: &str = "/sys/class/tpm/tpm0";
const MAX_REPORT_DATA: usize = 64;

/// RSA EK certificate NV index (TCG standard).
const EK_CERT_NV_INDEX: u32 = 0x01C0_0002;

pub fn is_available() -> bool {
    std::path::Path::new(TPM_DEVICE_PATH).exists() || std::path::Path::new(TPM_SYSFS_PATH).exists()
}

/// Generate TPM attestation evidence.
///
/// Creates a transient Attestation Key (AK) under the Storage Root Key,
/// generates a TPM2_Quote with the provided report_data as qualifyingData,
/// and reads PCR values for SHA-256 banks 0-23.
pub async fn generate_evidence(report_data: &[u8]) -> Result<TpmEvidence> {
    use tss_esapi::{
        attributes::ObjectAttributesBuilder,
        interface_types::{
            algorithm::{HashingAlgorithm, PublicAlgorithm, RsaSchemeAlgorithm},
            key_bits::RsaKeyBits,
            resource_handles::Hierarchy,
        },
        structures::{
            Data, PcrSelectionListBuilder, PcrSlot, PublicBuilder, PublicKeyRsa,
            PublicRsaParametersBuilder, RsaExponent, RsaScheme, SignatureScheme,
            SymmetricDefinition, SymmetricDefinitionObject,
        },
        tcti_ldr::{DeviceConfig, TctiNameConf},
        traits::Marshall,
        Context,
    };

    if report_data.len() > MAX_REPORT_DATA {
        return Err(AttestationError::ReportDataTooLarge {
            max: MAX_REPORT_DATA,
        });
    }

    let tcti =
        TctiNameConf::Device(DeviceConfig::from_str(TPM_DEVICE_PATH).map_err(|e| {
            AttestationError::HardwareAccessFailed(format!("TPM device config: {e}"))
        })?);

    let mut context = Context::new(tcti).map_err(|e| {
        AttestationError::HardwareAccessFailed(format!("TPM context creation failed: {e}"))
    })?;

    let session = context
        .start_auth_session(
            None,
            None,
            None,
            tss_esapi::constants::SessionType::Hmac,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .map_err(|e| AttestationError::HardwareAccessFailed(format!("auth session: {e}")))?
        .ok_or_else(|| {
            AttestationError::HardwareAccessFailed("failed to create auth session".into())
        })?;

    context.set_sessions((Some(session), None, None));

    // SRK: RSA 2048, restricted, decrypt
    let srk_public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(
            ObjectAttributesBuilder::new()
                .with_fixed_tpm(true)
                .with_fixed_parent(true)
                .with_sensitive_data_origin(true)
                .with_user_with_auth(true)
                .with_restricted(true)
                .with_decrypt(true)
                .build()
                .map_err(|e| {
                    AttestationError::HardwareAccessFailed(format!("SRK attributes: {e}"))
                })?,
        )
        .with_rsa_parameters(
            PublicRsaParametersBuilder::new()
                .with_scheme(RsaScheme::Null)
                .with_key_bits(RsaKeyBits::Rsa2048)
                .with_exponent(RsaExponent::default())
                .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
                .build()
                .map_err(|e| {
                    AttestationError::HardwareAccessFailed(format!("SRK RSA params: {e}"))
                })?,
        )
        .with_rsa_unique_identifier(PublicKeyRsa::default())
        .build()
        .map_err(|e| AttestationError::HardwareAccessFailed(format!("SRK public: {e}")))?;

    let srk_result = context
        .create_primary(Hierarchy::Owner, srk_public, None, None, None, None)
        .map_err(|e| AttestationError::HardwareAccessFailed(format!("create SRK: {e}")))?;

    let srk_handle = srk_result.key_handle;

    // AK: RSA 2048, restricted, sign, RSASSA SHA-256
    let ak_public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(
            ObjectAttributesBuilder::new()
                .with_fixed_tpm(true)
                .with_fixed_parent(true)
                .with_sensitive_data_origin(true)
                .with_user_with_auth(true)
                .with_restricted(true)
                .with_sign_encrypt(true)
                .build()
                .map_err(|e| {
                    AttestationError::HardwareAccessFailed(format!("AK attributes: {e}"))
                })?,
        )
        .with_rsa_parameters(
            PublicRsaParametersBuilder::new()
                .with_scheme(
                    RsaScheme::create(RsaSchemeAlgorithm::RsaSsa, Some(HashingAlgorithm::Sha256))
                        .map_err(|e| {
                        AttestationError::HardwareAccessFailed(format!("AK scheme: {e}"))
                    })?,
                )
                .with_key_bits(RsaKeyBits::Rsa2048)
                .with_exponent(RsaExponent::default())
                .with_symmetric(SymmetricDefinitionObject::Null)
                .build()
                .map_err(|e| {
                    AttestationError::HardwareAccessFailed(format!("AK RSA params: {e}"))
                })?,
        )
        .with_rsa_unique_identifier(PublicKeyRsa::default())
        .build()
        .map_err(|e| AttestationError::HardwareAccessFailed(format!("AK public: {e}")))?;

    let ak_result = context
        .create(srk_handle, ak_public, None, None, None, None)
        .map_err(|e| AttestationError::HardwareAccessFailed(format!("create AK: {e}")))?;

    let ak_handle = context
        .load(
            srk_handle,
            ak_result.out_private,
            ak_result.out_public.clone(),
        )
        .map_err(|e| AttestationError::HardwareAccessFailed(format!("load AK: {e}")))?;

    let pcr_slots: Vec<PcrSlot> = (0..24u32).map(|i| PcrSlot::try_from(i).unwrap()).collect();

    let pcr_selection = PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &pcr_slots)
        .build()
        .map_err(|e| AttestationError::HardwareAccessFailed(format!("PCR selection: {e}")))?;

    let qualifying_data = Data::try_from(report_data)
        .map_err(|e| AttestationError::HardwareAccessFailed(format!("qualifying data: {e}")))?;

    let (attest, signature) = context
        .quote(
            ak_handle.into(),
            qualifying_data,
            SignatureScheme::Null,
            pcr_selection.clone(),
        )
        .map_err(|e| AttestationError::HardwareAccessFailed(format!("TPM2_Quote: {e}")))?;

    // pcr_read returns (update_counter, pcr_selection_out, digest_list)
    let (_, _, pcr_digests) = context
        .pcr_read(pcr_selection)
        .map_err(|e| AttestationError::HardwareAccessFailed(format!("PCR read: {e}")))?;

    let ak_pub_bytes = ak_result
        .out_public
        .marshall()
        .map_err(|e| AttestationError::HardwareAccessFailed(format!("marshal AK public: {e}")))?;

    let ek_cert = read_ek_cert(&mut context);

    let _ = context.flush_context(ak_handle.into());
    let _ = context.flush_context(srk_handle.into());

    let sig_bytes = signature
        .marshall()
        .map_err(|e| AttestationError::HardwareAccessFailed(format!("marshal signature: {e}")))?;
    let attest_bytes = attest
        .marshall()
        .map_err(|e| AttestationError::HardwareAccessFailed(format!("marshal attest: {e}")))?;

    // DigestList.value() returns &[Digest], each Digest derefs to &[u8]
    let pcr_values: Vec<String> = pcr_digests
        .value()
        .iter()
        .map(|digest| hex::encode(digest.value()))
        .collect();

    let mut pcrs = pcr_values;
    pcrs.resize(24, "00".repeat(32));

    Ok(TpmEvidence {
        version: 1,
        tpm_quote: TpmQuote {
            signature: hex::encode(&sig_bytes),
            message: hex::encode(&attest_bytes),
            pcrs,
        },
        ak_pub: hex::encode(&ak_pub_bytes),
        ek_cert,
    })
}

/// Returns None if the NV index doesn't exist or can't be read.
fn read_ek_cert(context: &mut tss_esapi::Context) -> Option<String> {
    use tss_esapi::handles::NvIndexTpmHandle;
    use tss_esapi::interface_types::resource_handles::NvAuth;

    let nv_tpm_handle = NvIndexTpmHandle::new(EK_CERT_NV_INDEX).ok()?;

    // Convert TPM handle to ESYS handle via the resource manager
    let nv_handle = context
        .execute_without_session(|ctx| ctx.tr_from_tpm_public(nv_tpm_handle.into()))
        .ok()?
        .into();

    let (nv_public, _) = context.nv_read_public(nv_handle).ok()?;
    let size = nv_public.data_size() as u16;
    let data = context.nv_read(NvAuth::Owner, nv_handle, size, 0).ok()?;

    Some(hex::encode(data.value()))
}
