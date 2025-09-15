
use crate::certs::{AmdChain, Vcek};
use crate::HttpError;
use pem::parse_many;
use sev::firmware::guest::AttestationReport;
use thiserror::Error;
use x509_cert::der::Decode;
use x509_cert::Certificate;

const KDS_CERT_SITE: &str = "https://kdsintf.amd.com";
const KDS_VCEK: &str = "/vcek/v1";
const SEV_PROD_NAME: &str = "Genoa";
const KDS_CERT_CHAIN: &str = "cert_chain";

async fn get(url: &str) -> Result<Vec<u8>, HttpError> {
    let response = reqwest::get(url).await?; // Remove ::blocking
    let bytes = response.bytes().await?;
    Ok(bytes.to_vec())
}

#[derive(Error, Debug)]
pub enum AmdKdsError {
    #[error("X.509 certificate error: {0}")]
    X509(#[from] x509_cert::der::Error),
    #[error("PEM parsing error: {0}")]
    Pem(#[from] pem::PemError),
    #[error("Http error")]
    Http(#[from] HttpError),
    #[error("Certificate chain parsing error: expected 2 certificates, found {0}")]
    InvalidChainLength(usize),
}

/// Retrieve the AMD chain of trust (ASK & ARK) from AMD's KDS
pub async fn get_cert_chain() -> Result<AmdChain, AmdKdsError> {
    // Make async
    let url = format!("{KDS_CERT_SITE}{KDS_VCEK}/{SEV_PROD_NAME}/{KDS_CERT_CHAIN}");
    let bytes = get(&url).await?; // Add .await

    // Parse PEM certificates
    let pem_objects = parse_many(&bytes)?;

    if pem_objects.len() != 2 {
        return Err(AmdKdsError::InvalidChainLength(pem_objects.len()));
    }

    // Convert PEM to Certificate objects
    let ask = Certificate::from_der(&pem_objects[0].contents())?;
    let ark = Certificate::from_der(&pem_objects[1].contents())?;

    let chain = AmdChain { ask, ark };

    Ok(chain)
}

fn hexify(bytes: &[u8]) -> String {
    let mut hex_string = String::new();
    for byte in bytes {
        hex_string.push_str(&format!("{byte:02x}"));
    }
    hex_string
}

/// Retrieve a VCEK cert from AMD's KDS, based on an AttestationReport's platform information
pub async fn get_vcek(report: &AttestationReport) -> Result<Vcek, AmdKdsError> {
    let hw_id = hexify(&*report.chip_id);
    let url = format!(
        "{KDS_CERT_SITE}{KDS_VCEK}/{SEV_PROD_NAME}/{hw_id}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
        report.reported_tcb.bootloader,
        report.reported_tcb.tee,
        report.reported_tcb.snp,
        report.reported_tcb.microcode
    );

    println!("🔍 Fetching VCEK from URL: {}", url);
    println!("🔍 Chip ID: {}", hw_id);
    println!(
        "🔍 TCB levels: bl={:02}, tee={:02}, snp={:02}, ucode={:02}",
        report.reported_tcb.bootloader,
        report.reported_tcb.tee,
        report.reported_tcb.snp,
        report.reported_tcb.microcode
    );

    let bytes = get(&url).await?;
    println!("🔍 Received {} bytes from KDS", bytes.len());

    // Add some basic validation of the DER data
    println!(
        "🔍 First 32 bytes: {:02x?}",
        &bytes[..std::cmp::min(32, bytes.len())]
    );
    println!(
        "🔍 Last 32 bytes: {:02x?}",
        &bytes[bytes.len().saturating_sub(32)..]
    );

    let cert = Certificate::from_der(&bytes)?;
    println!("🔍 Successfully parsed VCEK certificate");

    let vcek = Vcek(cert);
    Ok(vcek)
}
