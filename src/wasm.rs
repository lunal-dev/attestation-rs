use crate::verify::verify_attestation;
use base64;

use js_sys::Promise;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;
use web_sys::console;

#[wasm_bindgen]
pub fn main() {
    console_error_panic_hook::set_once();
}

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
