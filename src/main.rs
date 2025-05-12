use std::fs;

mod pcs_client;
mod utils;

use flate2::read::GzDecoder;
use std::io::Read;

use dcap_rs::types::collaterals::IntelCollateral;
use dcap_rs::types::quotes::version_4::QuoteV4;
use dcap_rs::utils::quotes::version_4::verify_quote_dcapv4;
use lunal_attestation::utils::{extract_sgx_extensions_from_quote, parse_sgx_key_values};
use pcs_client::PcsClient;

async fn run_verification() -> Result<(), Box<dyn std::error::Error>> {
    let attestation_content = fs::read_to_string("example/attestation.txt")?;
    let compressed_bytes = base64::decode(attestation_content.trim())?;

    let mut decoder = GzDecoder::new(&compressed_bytes[..]);
    let mut quote_bytes = Vec::new();
    decoder.read_to_end(&mut quote_bytes)?;
    let quote = QuoteV4::from_bytes(&quote_bytes);

    let sgx_extensions = extract_sgx_extensions_from_quote(&quote.clone());
    let sgx_extension_key_values = parse_sgx_key_values(&sgx_extensions);

    let pcs_client = PcsClient::new();

    let tcb_response = pcs_client
        .get_tcb_info(&sgx_extension_key_values.fmspc)
        .await?;

    let qe_identity = pcs_client.get_qe_identity().await?;
    let pck_crl = pcs_client.get_pck_crl("platform", "der").await?;

    let mut collaterals = IntelCollateral::new();

    let tcb_info_bytes = tcb_response.json_to_bytes().unwrap();
    let qe_identity_bytes = serde_json::to_vec(&qe_identity).unwrap();
    let signing_cert_bytes = tcb_response.certs_to_bytes()[0].clone();

    collaterals.set_tcbinfo_bytes(&tcb_info_bytes);
    collaterals.set_qeidentity_bytes(&qe_identity_bytes);
    collaterals.set_sgx_platform_crl_der(&pck_crl);
    collaterals.set_sgx_tcb_signing_pem(&signing_cert_bytes);

    if let Ok(root_ca_bytes) = fs::read("data/Intel_SGX_Provisioning_Certification_RootCA.cer") {
        collaterals.set_intel_root_ca_der(&root_ca_bytes);
    }

    if let Ok(root_ca_crl_bytes) = fs::read("data/IntelSGXRootCA.der") {
        collaterals.set_sgx_intel_root_ca_crl_der(&root_ca_crl_bytes);
    }

    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    let verified_output = verify_quote_dcapv4(&quote, &collaterals, current_time);

    println!("Quote verification successful: {:?}", verified_output);
    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(e) = run_verification().await {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
