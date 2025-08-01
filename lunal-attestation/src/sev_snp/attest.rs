use sev_snp::{SevSnp, device::ReportOptions};

pub fn get_attestation_with_data(custom_data: &str) -> Result<&[u8], Box<dyn std::error::Error>> {
    // Initialize the SEV-SNP library
    let sev_snp = SevSnp::new()?;

    // Convert string to 64-byte array
    let mut report_data = [0u8; 64];
    let bytes = custom_data.as_bytes();
    let copy_len = std::cmp::min(bytes.len(), 64);
    report_data[..copy_len].copy_from_slice(&bytes[..copy_len]);

    // Create report options with custom data
    let options = ReportOptions {
        report_data: Some(report_data),
        vmpl: None,
    };

    // Get the attestation report with custom data
    let (report, var_data) = sev_snp.get_attestation_report_with_options(&options)?;

    println!("Attestation report generated successfully!");
    println!("Custom data used: {}", custom_data);
    println!("Report guest SVN: {}", report.guest_svn);
    println!("Report ID: {:02x?}", report.report_id);

    if let Some(data) = var_data {
        println!("Variable data length: {} bytes", data.len());
    }

    Ok((report.as_le_bytes().unwrap()))
}
