use crate::amd_azure::verify::{VerificationResult as VerifyResult, verify_compressed};
use js_sys::Promise;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

// Import the `console.log` function from the `console` module
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

// Define a macro for easier console logging
macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

#[wasm_bindgen]
pub struct VerificationResult {
    success: bool,
    message: String,
    report: Option<String>,
    certs: Option<String>,
    report_data: Option<String>,
}

#[wasm_bindgen]
impl VerificationResult {
    #[wasm_bindgen(getter)]
    pub fn success(&self) -> bool {
        self.success
    }

    #[wasm_bindgen(getter)]
    pub fn message(&self) -> String {
        self.message.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn report(&self) -> Option<String> {
        self.report.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn certs(&self) -> Option<String> {
        self.certs.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn report_data(&self) -> Option<String> {
        self.report_data.clone()
    }
}

#[wasm_bindgen]
pub fn verify_attestation_evidence(custom_data: &str, compressed_evidence: &str) -> Promise {
    let custom_data = custom_data.to_string();
    let compressed_evidence = compressed_evidence.to_string();

    future_to_promise(async move {
        // Convert string to bytes
        let custom_data_bytes = custom_data.as_bytes();

        // Verify the compressed evidence
        match verify_compressed(custom_data_bytes, &compressed_evidence).await {
            Ok(verify_result) => {
                let result = VerificationResult {
                    success: true,
                    message: "Attestation evidence verified successfully!".to_string(),
                    report: Some(serde_json::to_string(&verify_result.report).unwrap_or_default()),
                    certs: Some(serde_json::to_string(&verify_result.certs).unwrap_or_default()),
                    report_data: Some(verify_result.report_data),
                };
                Ok(JsValue::from(result))
            }
            Err(e) => {
                let result = VerificationResult {
                    success: false,
                    message: format!("Verification failed: {}", e),
                    report: None,
                    certs: None,
                    report_data: None,
                };
                Ok(JsValue::from(result))
            }
        }
    })
}
