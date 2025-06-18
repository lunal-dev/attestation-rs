use crate::utils::{extract_sgx_extensions_from_quote, parse_sgx_key_values};
use crate::verify::{fetch_collaterals, verify_attestation};
// use crate::wasm_verify::verify_quote_dcapv4_with_logging;
use base64;
use dcap_rs::types::quotes::version_4::QuoteV4;
use dcap_rs::utils::quotes::version_4::verify_quote_dcapv4;
use flate2::read::GzDecoder;
use js_sys::Promise;
use std::io::Read;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;
use web_sys::console;

#[wasm_bindgen]
pub fn main() {
    console_error_panic_hook::set_once();
}

// #[wasm_bindgen]
// pub fn test_dcap_verification_detailed(attestation_header: &str) -> Promise {
//     let attestation_header = attestation_header.to_string();

//     future_to_promise(async move {
//         console::log_1(&"🚀 Starting detailed DCAP verification test".into());

//         // Step 1: Parse attestation
//         console::log_1(&"📋 Step 1: Parsing attestation header".into());
//         let quote = match parse_attestation_header(&attestation_header) {
//             Ok(q) => {
//                 console::log_1(&"✅ Attestation parsed successfully".into());
//                 q
//             }
//             Err(e) => {
//                 console::error_1(&format!("❌ Parse error: {}", e).into());
//                 return Err(JsValue::from_str(&format!("Parse error: {}", e)));
//             }
//         };

//         // Step 2: Extract SGX extensions
//         console::log_1(&"📋 Step 2: Extracting SGX extensions".into());
//         let sgx_extensions = match extract_sgx_extensions_from_quote(&quote) {
//             Ok(ext) => {
//                 console::log_1(&"✅ SGX extensions extracted".into());
//                 ext
//             }
//             Err(e) => {
//                 console::error_1(&format!("❌ Extension error: {}", e).into());
//                 return Err(JsValue::from_str(&format!("Extension error: {}", e)));
//             }
//         };

//         let sgx_key_values = parse_sgx_key_values(&sgx_extensions);
//         console::log_1(&format!("   FMSPC: {}", sgx_key_values.fmspc).into());

//         // Step 3: Fetch collaterals
//         console::log_1(&"📋 Step 3: Fetching collaterals".into());
//         let collaterals = match fetch_collaterals(&sgx_key_values.fmspc).await {
//             Ok(c) => {
//                 console::log_1(&"✅ Collaterals fetched successfully".into());
//                 c
//             }
//             Err(e) => {
//                 console::error_1(&format!("❌ Collateral error: {}", e).into());
//                 return Err(JsValue::from_str(&format!("Collateral error: {}", e)));
//             }
//         };

//         // Step 4: Perform detailed verification
//         console::log_1(&"📋 Step 4: Starting detailed verification".into());

//         // Use fixed timestamp for testing (2025-06-11 07:43:36 UTC)
//         let current_time = chrono::Utc::now().timestamp() as u64;
//         console::log_1(&format!("   Using fixed time for testing: {}", current_time).into());

//         // match verify_quote_dcapv4(&quote, &collaterals, current_time) {
//         //     Ok(verified_output) => {
//         //         console::log_1(&"🎉 Verification completed successfully!".into());
//         //         let result = format!("{:#?}", verified_output);
//         //         Ok(JsValue::from_str(&result))
//         //     }
//         //     Err(e) => {
//         //         console::error_1(&format!("❌ Verification failed: {}", e).into());
//         //         Err(JsValue::from_str(&format!("Verification failed: {}", e)))
//         //     }
//         // }

//         let quote = verify_quote_dcapv4(&quote, &collaterals, current_time);
//         let result = format!("{:#?}", quote);
//         Ok(JsValue::from_str(&result))
//     })
// }

// fn parse_attestation_header(attestation_header: &str) -> Result<QuoteV4, String> {
//     let trimmed = attestation_header.trim();

//     // Decode base64
//     let compressed_bytes =
//         base64::decode(trimmed).map_err(|e| format!("Base64 decode failed: {}", e))?;

//     // Decompress gzip
//     let mut decoder = GzDecoder::new(&compressed_bytes[..]);
//     let mut quote_bytes = Vec::new();
//     decoder
//         .read_to_end(&mut quote_bytes)
//         .map_err(|e| format!("Gzip decompression failed: {}", e))?;

//     // Parse quote
//     let quote = QuoteV4::from_bytes(&quote_bytes);
//     Ok(quote)
// }

// Single attestation verification
#[wasm_bindgen]
pub fn verify_single_attestation(attestation_header: &str) -> Promise {
    let attestation_header = attestation_header.to_string();

    future_to_promise(async move {
        match verify_attestation(&attestation_header).await {
            Ok(verified_output) => {
                let result = format!("{:#?}", verified_output);
                Ok(JsValue::from_str(&result))
            }
            Err(e) => Err(JsValue::from_str(&e.to_string())),
        }
    })
}
