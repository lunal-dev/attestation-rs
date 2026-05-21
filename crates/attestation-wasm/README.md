# attestation-wasm

WebAssembly bindings for `attestation::verify` — verify a TEE attestation
evidence envelope from JavaScript. Useful when the relying party that wants
to gate code on an attestation result runs in the browser, an Edge worker,
or any other JS runtime.

Verification only. Evidence generation requires hardware access and is not
exposed here.

## What you get

A single async function, exported by `pkg/attestation_wasm.js`:

```ts
function verify(
  evidence_json: string,
  expected_report_data?: Uint8Array | null,
): Promise<string>;
```

- `evidence_json` — an [`AttestationEvidence`] envelope, as the JSON string
  produced by the Rust library's `attest()` or the `attestation-cli attest`
  command. Self-describing (carries the `platform` tag), so the same JS
  call handles every supported TEE.
- `expected_report_data` — optional raw bytes the caller expects to find in
  the report's `report_data` / TPM nonce field. Pass `undefined` to skip
  the binding check.
- Returns a [`VerificationResult`] serialized to JSON. Throws on any
  verification failure — bad signature, malformed envelope, wrong
  `report_data`, init-data mismatch, TCB violation, etc. A returned
  result always means every check the verifier ran succeeded; treat
  thrown errors as "did not attest", not "transient failure".

The JSON shape is the same as `attestation::VerificationResult` in the parent
crate; the top-level fields you'll usually read are:

| Field                | Meaning                                                              |
| -------------------- | -------------------------------------------------------------------- |
| `signature_valid`    | `true` iff the platform signature chain verified                     |
| `platform`           | `"snp"`, `"tdx"`, `"az-snp"`, `"az-tdx"`, `"gcp-snp"`, `"gcp-tdx"`, … |
| `claims.launch_digest` | hex measurement (MRTD for TDX, launch digest for SNP)             |
| `report_data_match`  | `true` if you passed `expected_report_data`, `null` if you didn't    |
| `collateral_verified`| CRL / TCB collateral fully checked                                   |

Supported platforms mirror the parent crate's verify side: AMD SEV-SNP (bare-metal,
Azure, GCP), Intel TDX (bare-metal, Azure, GCP), dstack TDX.

[`AttestationEvidence`]: ../../src/types.rs
[`VerificationResult`]: ../../src/types.rs

## Building

`wasm-pack` produces a `pkg/` directory containing the `.wasm`, the
auto-generated JS glue, and a `package.json`. Pick the `--target` that
matches your runtime:

```bash
# Node.js (CommonJS-style import)
wasm-pack build --target nodejs

# Bundlers (webpack, Vite, Rollup, esbuild, …)
wasm-pack build --target bundler

# Native ES modules in the browser (no bundler)
wasm-pack build --target web

# Plain <script> tag
wasm-pack build --target no-modules
```

All targets emit the same `verify` function. The Node target loads the
`.wasm` synchronously via `fs`; the `bundler` and `web` targets require
either bundler integration or an explicit `init()` call to instantiate the
module (see [wasm-pack docs](https://rustwasm.github.io/docs/wasm-pack/commands/build.html#target)).

## Using it from Node.js

```js
import { verify } from './pkg/attestation_wasm.js';

// `evidenceJson` is the string produced by an attester somewhere else.
// On a TEE host that's `attestation::attest()` or `attestation-cli attest`.
const evidenceJson = await fetch('/attest').then(r => r.text());

const expected = new TextEncoder().encode('my-challenge-nonce');

let result;
try {
  result = JSON.parse(await verify(evidenceJson, expected));
} catch (e) {
  // Any verification check that fails throws — wrong report_data, bad
  // signature, expired collateral, etc. Treat this as "did not attest".
  throw new Error(`attestation rejected: ${e.message}`);
}

console.log(`Verified ${result.platform}, launch digest ${result.claims.launch_digest}`);
```

The verifier needs network access to fetch platform collateral (AMD VCEK
chain, Intel PCS for TDX, etc.). In Node 18+ the global `fetch` is used
automatically; older runtimes need a `fetch` polyfill.

## Using it from a bundler / browser

With `wasm-pack build --target bundler` and a bundler that handles `.wasm`
imports (Vite, webpack 5+, Rollup with `@rollup/plugin-wasm`, esbuild with
the `loader: { '.wasm': 'file' }` plugin):

```js
import init, { verify } from 'attestation-wasm';

await init(); // bundler-managed targets often skip this; check your tooling

const result = JSON.parse(await verify(evidenceJson, expected));
```

For `--target web` without a bundler, call `init()` with an explicit URL:

```js
import init, { verify } from './pkg/attestation_wasm.js';
await init('./pkg/attestation_wasm_bg.wasm');
```

CORS rules apply to the collateral fetches the verifier makes
(`kdsintf.amd.com`, Intel PCS, etc.). If your browser environment can't
reach those hosts directly, proxy them through your own backend.

## End-to-end example

`example.mjs` in this directory generates fresh evidence with the host
CLI, then verifies it through the WASM module — including the negative
case where the nonce doesn't match. Run it on a CVM:

```bash
# Build the CLI with attestation enabled (requires Linux + TEE hardware)
cargo build --features cli,attest

# Build the wasm package
cd crates/attestation-wasm
wasm-pack build --target nodejs

# Run the round-trip
node example.mjs
```

## `report_data` size

Pass the original challenge bytes — don't pre-pad. The verifier
zero-pads `expected_report_data` up to whatever the on-quote field size
is (50 bytes for Azure vTPM TPM2B_DATA, 64 bytes for SNP/TDX report
fields). Passing more bytes than fit in the on-quote field errors with
`report_data exceeds maximum size`.

## License

Apache-2.0.
