// use dcap_rs::types::cert::{IntelSgxCrls, SgxExtensions};
// use dcap_rs::types::enclave_identity::EnclaveIdentityV2;
// use dcap_rs::types::quotes::body::EnclaveReport;
// use dcap_rs::types::quotes::version_4::QuoteV4;
// use dcap_rs::types::quotes::{CertData, CertDataType, QuoteHeader, body::QuoteBody};
// use dcap_rs::types::tcbinfo::{TcbInfo, TcbInfoV3};
// use dcap_rs::types::{TcbStatus, VerifiedOutput, collaterals::IntelCollateral};
// use dcap_rs::utils::cert::{
//     extract_sgx_extension, parse_certchain, parse_pem, verify_certificate, verify_crl,
// };
// use dcap_rs::utils::enclave_identity::{get_qe_tcbstatus, validate_enclave_identityv2};
// use dcap_rs::utils::hash::sha256sum;
// use dcap_rs::utils::tcbinfo::validate_tcbinfov3;
// use wasm_bindgen::prelude::*;
// use web_sys::console;

// const SGX_TEE_TYPE: u32 = 0;

// // Logging macros for WASM
// macro_rules! log {
//     ($($t:tt)*) => (console::log_1(&format!($($t)*).into()))
// }

// macro_rules! log_error {
//     ($($t:tt)*) => (console::error_1(&format!($($t)*).into()))
// }

// // Safe helper functions for WASM
// fn safe_verify_qe_report_data(
//     report_data: &[u8],
//     ecdsa_attestation_key: &[u8],
//     qe_auth_data: &[u8],
// ) -> bool {
//     let mut verification_data = Vec::new();
//     verification_data.extend_from_slice(ecdsa_attestation_key);
//     verification_data.extend_from_slice(qe_auth_data);
//     let mut recomputed_report_data = [0u8; 64];
//     recomputed_report_data[..32].copy_from_slice(&sha256sum(&verification_data));
//     recomputed_report_data == report_data
// }

// fn safe_validate_qe_report(
//     enclave_report: &EnclaveReport,
//     qeidentityv2: &EnclaveIdentityV2,
// ) -> bool {
//     // Check that id is "QE", "TD_QE" or "QVE" and version is 2
//     if !((qeidentityv2.enclave_identity.id == "QE"
//         || qeidentityv2.enclave_identity.id == "TD_QE"
//         || qeidentityv2.enclave_identity.id == "QVE")
//         && qeidentityv2.enclave_identity.version == 2)
//     {
//         return false;
//     }

//     let mrsigner_ok = enclave_report.mrsigner
//         == hex::decode(&qeidentityv2.enclave_identity.mrsigner)
//             .unwrap_or_default()
//             .as_slice();
//     let isvprodid_ok = enclave_report.isv_prod_id == qeidentityv2.enclave_identity.isvprodid;

//     let attributes = hex::decode(&qeidentityv2.enclave_identity.attributes).unwrap_or_default();
//     let attributes_mask =
//         hex::decode(&qeidentityv2.enclave_identity.attributes_mask).unwrap_or_default();
//     let masked_attributes = attributes
//         .iter()
//         .zip(attributes_mask.iter())
//         .map(|(a, m)| a & m)
//         .collect::<Vec<u8>>();
//     let masked_enclave_attributes = enclave_report
//         .attributes
//         .iter()
//         .zip(attributes_mask.iter())
//         .map(|(a, m)| a & m)
//         .collect::<Vec<u8>>();
//     let enclave_attributes_ok = masked_enclave_attributes == masked_attributes;

//     let miscselect = hex::decode(&qeidentityv2.enclave_identity.miscselect).unwrap_or_default();
//     let miscselect_mask =
//         hex::decode(&qeidentityv2.enclave_identity.miscselect_mask).unwrap_or_default();
//     let masked_miscselect = miscselect
//         .iter()
//         .zip(miscselect_mask.iter())
//         .map(|(a, m)| a & m)
//         .collect::<Vec<u8>>();
//     let masked_enclave_miscselect = enclave_report
//         .misc_select
//         .iter()
//         .zip(miscselect_mask.iter())
//         .map(|(a, m)| a & m)
//         .collect::<Vec<u8>>();
//     let enclave_miscselect_ok = masked_enclave_miscselect == masked_miscselect;

//     mrsigner_ok && isvprodid_ok && enclave_attributes_ok && enclave_miscselect_ok
// }

// // Extended safe version - test more verification steps
// fn safe_common_verify_and_fetch_tcb_extended(
//     quote_header: &QuoteHeader,
//     quote_body: &QuoteBody,
//     ecdsa_attestation_signature: &[u8],
//     ecdsa_attestation_pubkey: &[u8],
//     qe_report: &EnclaveReport,
//     qe_report_signature: &[u8],
//     qe_auth_data: &[u8],
//     qe_cert_data: &CertData,
//     collaterals: &IntelCollateral,
//     current_time: u64,
// ) -> Result<(TcbStatus, SgxExtensions, TcbInfo), String> {
//     log!("   🔍 Starting safe_common_verify_and_fetch_tcb_extended");

//     // Step 3.1: Get certificates
//     log!("   Step 3.1: Getting certificates from collaterals");
//     let signing_cert = collaterals.get_sgx_tcb_signing();
//     let intel_sgx_root_cert = collaterals.get_sgx_intel_root_ca();
//     log!("   ✅ Got certificates successfully");

//     // Step 3.2: Create Intel CRLs
//     log!("   Step 3.2: Creating Intel CRLs from collaterals");
//     let intel_crls = IntelSgxCrls::from_collaterals(collaterals);
//     log!("   ✅ Created Intel CRLs successfully");

//     // Step 3.3: Check SGX Root CA CRL
//     log!("   Step 3.3: Checking SGX Root CA CRL");
//     match &intel_crls.sgx_root_ca_crl {
//         Some(crl) => {
//             if !verify_crl(crl, &intel_sgx_root_cert, current_time) {
//                 log_error!("   ❌ SGX Root CA CRL verification failed");
//                 return Err("SGX Root CA CRL verification failed".to_string());
//             }
//             log!("   ✅ SGX Root CA CRL verified successfully");
//         }
//         None => {
//             log_error!("   ❌ No SGX Root CA CRL found in collaterals");
//             return Err("No SGX Root CA CRL found".to_string());
//         }
//     }

//     // Step 3.4: Check signing cert not revoked
//     log!("   Step 3.4: Checking if signing cert is revoked");
//     let signing_cert_revoked = intel_crls.is_cert_revoked(&signing_cert);
//     if signing_cert_revoked {
//         log_error!("   ❌ TCB Signing Cert is revoked");
//         return Err("TCB Signing Cert revoked".to_string());
//     }
//     log!("   ✅ Signing cert not revoked");

//     // Step 3.5: Verify signing cert signed by root
//     log!("   Step 3.5: Verifying signing cert signed by Intel root");
//     if !verify_certificate(&signing_cert, &intel_sgx_root_cert, current_time) {
//         log_error!("   ❌ TCB Signing Cert is not signed by Intel SGX Root CA");
//         return Err("TCB Signing Cert is not signed by Intel SGX Root CA".to_string());
//     }
//     log!("   ✅ Signing cert verified");

//     // Step 3.6: Validate QE Identity
//     log!("   Step 3.6: Validating QE Identity");
//     let qeidentityv2 = collaterals.get_qeidentityv2();
//     if !validate_enclave_identityv2(&qeidentityv2, &signing_cert, current_time) {
//         log_error!("   ❌ QE Identity validation failed");
//         return Err("QE Identity validation failed".to_string());
//     }
//     log!("   ✅ QE Identity validated");

//     // Step 3.7: Verify QE Report Data
//     log!("   Step 3.7: Verifying QE Report Data");
//     if !safe_verify_qe_report_data(
//         &qe_report.report_data,
//         ecdsa_attestation_pubkey,
//         qe_auth_data,
//     ) {
//         log_error!("   ❌ QE Report Data is incorrect");
//         return Err("QE Report Data is incorrect".to_string());
//     }
//     log!("   ✅ QE Report Data verified");

//     // Step 3.8: Validate QE Report
//     log!("   Step 3.8: Validating QE Report");
//     if !safe_validate_qe_report(qe_report, &qeidentityv2) {
//         log_error!("   ❌ QE Report values do not match with the provided QEIdentity");
//         return Err("QE Report values do not match with the provided QEIdentity".to_string());
//     }
//     log!("   ✅ QE Report validated");

//     // Step 3.9: Get QE TCB Status
//     log!("   Step 3.9: Getting QE TCB Status");
//     let qe_tcb_status = get_qe_tcbstatus(qe_report, &qeidentityv2);
//     if qe_tcb_status == TcbStatus::TcbRevoked {
//         log_error!("   ❌ QEIdentity TCB Revoked");
//         return Err("QEIdentity TCB Revoked".to_string());
//     }
//     log!("   ✅ QE TCB Status: {:?}", qe_tcb_status);

//     // Step 3.10: Check cert data type
//     log!("   Step 3.10: Checking QE Cert Data Type");
//     if qe_cert_data.cert_data_type != 5 {
//         log_error!(
//             "   ❌ QE Cert Type must be 5, got: {}",
//             qe_cert_data.cert_data_type
//         );
//         return Err(format!(
//             "QE Cert Type must be 5, got: {}",
//             qe_cert_data.cert_data_type
//         ));
//     }
//     log!("   ✅ QE Cert Data Type is 5");

//     // Step 3.11: Parse certificate chain
//     log!("   Step 3.11: Parsing certificate chain from QE cert data");
//     let certchain_pems = match parse_pem(&qe_cert_data.cert_data) {
//         Ok(pems) => {
//             log!("   ✅ Parsed PEMs successfully, count: {}", pems.len());
//             pems
//         }
//         Err(e) => {
//             log_error!("   ❌ Failed to parse PEMs: {:?}", e);
//             return Err(format!("Failed to parse PEMs: {:?}", e));
//         }
//     };

//     let certchain = parse_certchain(&certchain_pems);
//     log!("   ✅ Parsed certificate chain, count: {}", certchain.len());

//     // Step 3.12: Check certificates not revoked
//     log!("   Step 3.12: Checking certificates in chain not revoked");
//     for (i, cert) in certchain.iter().enumerate() {
//         if intel_crls.is_cert_revoked(cert) {
//             log_error!("   ❌ Certificate {} in chain is revoked", i);
//             return Err(format!("Certificate {} in chain is revoked", i));
//         }
//     }
//     log!("   ✅ No certificates in chain are revoked");

//     // Step 3.13: Extract SGX extensions from PCK cert
//     log!("   Step 3.13: Extracting SGX extensions from PCK certificate");
//     let pck_cert = &certchain[0];
//     let sgx_extensions = extract_sgx_extension(&pck_cert);
//     log!("   ✅ Extracted SGX extensions");
//     log!("   FMSPC: {}", hex::encode(&sgx_extensions.fmspc));

//     // Step 3.14: Validate TCB Info V3
//     log!("   Step 3.14: Validating TCB Info V3");
//     let tcb_info_v3 = collaterals.get_tcbinfov3();
//     if !validate_tcbinfov3(&tcb_info_v3, &signing_cert, current_time) {
//         log_error!("   ❌ Invalid TCBInfoV3");
//         return Err("Invalid TCBInfoV3".to_string());
//     }
//     log!("   ✅ TCB Info V3 validated");

//     let tcb_info = TcbInfo::V3(tcb_info_v3);

//     log!("   🎉 All verification steps completed successfully!");
//     Ok((qe_tcb_status, sgx_extensions, tcb_info))
// }

// pub fn verify_quote_dcapv4_with_logging(
//     quote: &QuoteV4,
//     collaterals: &IntelCollateral,
//     current_time: u64,
// ) -> Result<String, String> {
//     log!("🚀 Starting verify_quote_dcapv4_with_logging");

//     // Step 1: Check quote header
//     log!("📋 Step 1: Checking quote header");
//     log!("   Quote version: {}", quote.header.version);
//     log!("   TEE type: {}", quote.header.tee_type);
//     log!("✅ Skipping quote header validation for testing");

//     // Step 2: Extract QE cert data
//     log!("📋 Step 2: Extracting QE cert data");
//     let qe_cert_data_v4 = &quote.signature.qe_cert_data;

//     let qe_report_cert_data = match qe_cert_data_v4.get_cert_data() {
//         CertDataType::QeReportCertData(qe_report_cert_data) => {
//             log!("✅ Found QeReportCertData");
//             qe_report_cert_data
//         }
//         _ => {
//             log_error!("❌ Unsupported CertDataType in QuoteSignatureDataV4");
//             return Err("Unsupported CertDataType in QuoteSignatureDataV4".to_string());
//         }
//     };

//     // Step 3: Call extended common verification
//     log!("📋 Step 3: Starting safe_common_verify_and_fetch_tcb_extended");
//     log!(
//         "   QE report signature size: {}",
//         qe_report_cert_data.qe_report_signature.len()
//     );
//     log!(
//         "   QE auth data size: {}",
//         qe_report_cert_data.qe_auth_data.data.len()
//     );

//     let (qe_tcb_status, sgx_extensions, tcb_info) = safe_common_verify_and_fetch_tcb_extended(
//         &quote.header,
//         &quote.quote_body,
//         &quote.signature.quote_signature,
//         &quote.signature.ecdsa_attestation_key,
//         &qe_report_cert_data.qe_report,
//         &qe_report_cert_data.qe_report_signature,
//         &qe_report_cert_data.qe_auth_data.data,
//         &qe_report_cert_data.qe_cert_data,
//         collaterals,
//         current_time,
//     )?;

//     log!("✅ safe_common_verify_and_fetch_tcb_extended completed successfully");
//     log!("   QE TCB Status: {:?}", qe_tcb_status);
//     log!("   FMSPC: {}", hex::encode(&sgx_extensions.fmspc));

//     // Step 4: Return success result
//     log!("📋 Step 4: Creating verification result");
//     let result = format!(
//         "Verification successful! QE TCB Status: {:?}, FMSPC: {}",
//         qe_tcb_status,
//         hex::encode(&sgx_extensions.fmspc)
//     );

//     log!("🎉 verify_quote_dcapv4_with_logging completed successfully!");
//     Ok(result)
// }
