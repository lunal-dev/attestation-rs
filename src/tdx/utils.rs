use dcap_rs::types::cert::SgxExtensions;
use dcap_rs::types::quotes::CertDataType;
use dcap_rs::utils::cert::extract_sgx_extension;
use dcap_rs::utils::cert::parse_certchain;
use dcap_rs::utils::cert::parse_pem;

use dcap_rs::types::quotes::version_4::QuoteV4;

pub fn extract_sgx_extensions_from_quote(
    quote: &QuoteV4,
) -> Result<SgxExtensions, Box<dyn std::error::Error>> {
    let qe_cert_data_v4 = &quote.signature.qe_cert_data;

    let qe_report_cert_data = if let CertDataType::QeReportCertData(qe_report_cert_data) =
        qe_cert_data_v4.get_cert_data()
    {
        qe_report_cert_data
    } else {
        return Err("Unsupported CertDataType in QuoteSignatureDataV4"
            .to_string()
            .into());
    };

    let qe_cert_data = &qe_report_cert_data.qe_cert_data;
    let certchain_pems = parse_pem(&qe_cert_data.cert_data).unwrap();
    let certchain = parse_certchain(&certchain_pems);
    let pck_cert = &certchain[0];
    let extensions = extract_sgx_extension(&pck_cert);

    Ok(extensions)
}

pub fn parse_sgx_key_values(extensions: &SgxExtensions) -> SgxKeyValues {
    SgxKeyValues {
        fmspc: hex::encode(extensions.fmspc).to_uppercase(),
        pceid: hex::encode(extensions.pceid).to_uppercase(),
        pcesvn: format!("{:04X}", extensions.tcb.pcesvn),
        ppid: extensions.ppid, // Keep as bytes for QEID usage
        ppid_hex: hex::encode(extensions.ppid).to_uppercase(),
    }
}

#[derive(Debug)]
pub struct SgxKeyValues {
    pub fmspc: String,
    pub pceid: String,
    pub pcesvn: String,
    pub ppid: [u8; 16],
    pub ppid_hex: String,
}
