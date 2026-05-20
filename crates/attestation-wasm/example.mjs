#!/usr/bin/env node
//
// Live attestation → WASM verification example.
//
// 1. Generates fresh attestation evidence with a report_data nonce (native CLI).
// 2. Verifies the envelope entirely in WASM. The verifier resolves collateral
//    (VCEK / DCAP collateral) over fetch from the appropriate provider, so the
//    caller only needs to pass the envelope and the nonce.
//
// Usage:
//   cargo build --features cli
//   cd crates/attestation-wasm && wasm-pack build --target nodejs
//   node example.mjs
//

import { execSync } from 'child_process';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const rootDir = join(__dirname, '..', '..');

// --- Step 1: Generate live evidence with a nonce ---
console.log('=== Step 1: Generating live attestation evidence ===\n');

const nonce = 'wasm-verify-' + Date.now();
console.log(`Nonce: "${nonce}"`);

const evidenceJson = execSync(
  `cargo run --manifest-path ${rootDir}/Cargo.toml --features cli --quiet -- attest --platform snp --report-data "${nonce}"`,
  { encoding: 'utf-8', timeout: 30000 }
).trim();

console.log(`Evidence envelope: ${evidenceJson.length} bytes`);

// --- Step 2: Verify in WASM (collateral fetched internally) ---
console.log('\n=== Step 2: Verifying in WASM (with report_data check) ===\n');

const wasm = await import('./pkg/attestation_wasm.js');
const nonceBytes = new TextEncoder().encode(nonce);

const t0 = performance.now();
const resultJson = await wasm.verify(evidenceJson, nonceBytes);
const elapsed = (performance.now() - t0).toFixed(1);
const result = JSON.parse(resultJson);

console.log(`Verified in ${elapsed}ms\n`);
console.log(JSON.stringify(result, null, 2));

// --- Step 3: Verify report_data mismatch is caught ---
console.log('\n=== Step 3: Verifying wrong report_data is rejected ===\n');

const wrongNonce = new TextEncoder().encode('wrong-nonce');
const mismatchJson = await wasm.verify(evidenceJson, wrongNonce);
const mismatch = JSON.parse(mismatchJson);
console.log(`report_data_match with wrong nonce: ${mismatch.report_data_match}`);

// --- Step 4: Verify without report_data check ---
console.log('\n=== Step 4: Verifying without report_data check ===\n');

const noCheckJson = await wasm.verify(evidenceJson, undefined);
const noCheck = JSON.parse(noCheckJson);
console.log(`report_data_match (no check): ${noCheck.report_data_match}`);

// --- Summary ---
console.log('\n=== Summary ===\n');
console.log(`Signature valid:      ${result.signature_valid}`);
console.log(`Report data match:    ${result.report_data_match}`);
console.log(`Platform:             ${result.platform}`);
console.log(`Launch digest:        ${result.claims.launch_digest}`);

if (!result.signature_valid) {
  console.error('\nFAILED: signature not valid');
  process.exit(1);
}
if (result.report_data_match !== true) {
  console.error('\nFAILED: report_data did not match nonce');
  process.exit(1);
}
if (mismatch.report_data_match !== false) {
  console.error('\nFAILED: wrong nonce was not rejected');
  process.exit(1);
}

console.log('\nPASSED: live evidence verified in WASM with report_data binding');
