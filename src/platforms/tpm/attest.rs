use std::{fmt::Display, path::Path, str::FromStr};

use tss_esapi::{
    attributes::ObjectAttributesBuilder,
    constants::SessionType,
    handles::{KeyHandle, NvIndexTpmHandle},
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm, RsaSchemeAlgorithm},
        key_bits::RsaKeyBits,
        resource_handles::{Hierarchy, NvAuth},
    },
    structures::{
        Attest, Data, DigestList, PcrSelectionList, PcrSelectionListBuilder, PcrSlot, Public,
        PublicBuilder, PublicKeyRsa, PublicRsaParametersBuilder, RsaExponent, RsaScheme, Signature,
        SignatureScheme, SymmetricDefinition, SymmetricDefinitionObject,
    },
    tcti_ldr::{DeviceConfig, TctiNameConf},
    traits::Marshall,
    Context,
};

use crate::error::{AttestationError, Result};
use crate::platforms::tpm_common::TpmQuote;

use super::evidence::TpmEvidence;

const TPM_DEVICE_PATH: &str = "/dev/tpmrm0";
const TPM_SYSFS_PATH: &str = "/sys/class/tpm/tpm0";
const MAX_REPORT_DATA: usize = 64;

/// RSA EK certificate NV index (TCG standard).
const EK_CERT_NV_INDEX: u32 = 0x01C0_0002;

pub fn is_available() -> bool {
    Path::new(TPM_DEVICE_PATH).exists() || Path::new(TPM_SYSFS_PATH).exists()
}

struct LoadedAk {
    handle: KeyHandle,
    public: Vec<u8>,
}

struct QuoteOutput {
    attest: Attest,
    signature: Signature,
    pcr_digests: DigestList,
}

/// Generate TPM attestation evidence.
///
/// Creates a transient Attestation Key (AK) under the Storage Root Key,
/// generates a TPM2_Quote with the provided report_data as qualifyingData,
/// and reads PCR values for SHA-256 banks 0-23.
pub async fn generate_evidence(report_data: &[u8]) -> Result<TpmEvidence> {
    validate_report_data(report_data)?;

    let mut context = create_context()?;
    start_hmac_session(&mut context)?;

    let srk_handle = create_srk(&mut context)?;
    let ak = create_and_load_ak(&mut context, srk_handle)?;
    let pcr_selection = sha256_pcr_selection()?;
    let quote = quote_pcrs(&mut context, ak.handle, report_data, pcr_selection)?;
    let ek_cert = read_ek_cert(&mut context);

    flush_loaded_keys(&mut context, ak.handle, srk_handle);

    build_evidence(ak.public, quote, ek_cert)
}

fn validate_report_data(report_data: &[u8]) -> Result<()> {
    if report_data.len() > MAX_REPORT_DATA {
        return Err(AttestationError::ReportDataTooLarge {
            max: MAX_REPORT_DATA,
        });
    }

    Ok(())
}

fn create_context() -> Result<Context> {
    let tcti = TctiNameConf::Device(
        DeviceConfig::from_str(TPM_DEVICE_PATH)
            .map_err(|e| hardware_error("TPM device config", e))?,
    );

    Context::new(tcti).map_err(|e| hardware_error("TPM context creation failed", e))
}

fn start_hmac_session(context: &mut Context) -> Result<()> {
    let session = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .map_err(|e| hardware_error("auth session", e))?
        .ok_or_else(|| {
            AttestationError::HardwareAccessFailed("failed to create auth session".into())
        })?;

    context.set_sessions((Some(session), None, None));

    Ok(())
}

fn create_srk(context: &mut Context) -> Result<KeyHandle> {
    let srk_public = build_srk_public()?;
    let srk_result = context
        .create_primary(Hierarchy::Owner, srk_public, None, None, None, None)
        .map_err(|e| hardware_error("create SRK", e))?;

    Ok(srk_result.key_handle)
}

fn build_srk_public() -> Result<Public> {
    PublicBuilder::new()
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
                .map_err(|e| hardware_error("SRK attributes", e))?,
        )
        .with_rsa_parameters(
            PublicRsaParametersBuilder::new()
                .with_scheme(RsaScheme::Null)
                .with_key_bits(RsaKeyBits::Rsa2048)
                .with_exponent(RsaExponent::default())
                .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
                .build()
                .map_err(|e| hardware_error("SRK RSA params", e))?,
        )
        .with_rsa_unique_identifier(PublicKeyRsa::default())
        .build()
        .map_err(|e| hardware_error("SRK public", e))
}

fn create_and_load_ak(context: &mut Context, srk_handle: KeyHandle) -> Result<LoadedAk> {
    let ak_public = build_ak_public()?;
    let ak_result = context
        .create(srk_handle, ak_public, None, None, None, None)
        .map_err(|e| hardware_error("create AK", e))?;

    let public = ak_result
        .out_public
        .marshall()
        .map_err(|e| hardware_error("marshal AK public", e))?;

    let handle = context
        .load(srk_handle, ak_result.out_private, ak_result.out_public)
        .map_err(|e| hardware_error("load AK", e))?;

    Ok(LoadedAk { handle, public })
}

fn build_ak_public() -> Result<Public> {
    PublicBuilder::new()
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
                .map_err(|e| hardware_error("AK attributes", e))?,
        )
        .with_rsa_parameters(
            PublicRsaParametersBuilder::new()
                .with_scheme(
                    RsaScheme::create(RsaSchemeAlgorithm::RsaSsa, Some(HashingAlgorithm::Sha256))
                        .map_err(|e| hardware_error("AK scheme", e))?,
                )
                .with_key_bits(RsaKeyBits::Rsa2048)
                .with_exponent(RsaExponent::default())
                .with_symmetric(SymmetricDefinitionObject::Null)
                .build()
                .map_err(|e| hardware_error("AK RSA params", e))?,
        )
        .with_rsa_unique_identifier(PublicKeyRsa::default())
        .build()
        .map_err(|e| hardware_error("AK public", e))
}

fn sha256_pcr_selection() -> Result<PcrSelectionList> {
    let pcr_slots: Vec<PcrSlot> = (0..24u32)
        .map(PcrSlot::try_from)
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| hardware_error("PCR slot", e))?;

    PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &pcr_slots)
        .build()
        .map_err(|e| hardware_error("PCR selection", e))
}

fn quote_pcrs(
    context: &mut Context,
    ak_handle: KeyHandle,
    report_data: &[u8],
    pcr_selection: PcrSelectionList,
) -> Result<QuoteOutput> {
    let qualifying_data =
        Data::try_from(report_data).map_err(|e| hardware_error("qualifying data", e))?;

    let (attest, signature) = context
        .quote(
            ak_handle,
            qualifying_data,
            SignatureScheme::Null,
            pcr_selection.clone(),
        )
        .map_err(|e| hardware_error("TPM2_Quote", e))?;

    let (_, _, pcr_digests) = context
        .pcr_read(pcr_selection)
        .map_err(|e| hardware_error("PCR read", e))?;

    Ok(QuoteOutput {
        attest,
        signature,
        pcr_digests,
    })
}

fn flush_loaded_keys(context: &mut Context, ak_handle: KeyHandle, srk_handle: KeyHandle) {
    let _ = context.flush_context(ak_handle.into());
    let _ = context.flush_context(srk_handle.into());
}

fn build_evidence(
    ak_pub_bytes: Vec<u8>,
    quote: QuoteOutput,
    ek_cert: Option<String>,
) -> Result<TpmEvidence> {
    let sig_bytes = quote
        .signature
        .marshall()
        .map_err(|e| hardware_error("marshal signature", e))?;
    let attest_bytes = quote
        .attest
        .marshall()
        .map_err(|e| hardware_error("marshal attest", e))?;

    Ok(TpmEvidence {
        version: 1,
        tpm_quote: TpmQuote {
            signature: hex::encode(&sig_bytes),
            message: hex::encode(&attest_bytes),
            pcrs: encode_pcrs(&quote.pcr_digests),
        },
        ak_pub: hex::encode(&ak_pub_bytes),
        ek_cert,
    })
}

fn encode_pcrs(pcr_digests: &DigestList) -> Vec<String> {
    let mut pcrs: Vec<String> = pcr_digests
        .value()
        .iter()
        .map(|digest| hex::encode(digest.value()))
        .collect();

    pcrs.resize(24, "00".repeat(32));
    pcrs
}

/// Returns None if the NV index doesn't exist or can't be read.
fn read_ek_cert(context: &mut Context) -> Option<String> {
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

fn hardware_error(operation: &str, error: impl Display) -> AttestationError {
    AttestationError::HardwareAccessFailed(format!("{operation}: {error}"))
}
