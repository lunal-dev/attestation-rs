# attestation-rs — Progress

## Status: Full TDX DCAP Verification Working End-to-End

156 tests pass (154 unit + 2 integration against live Intel PCS v4). Zero failures.

## Verification Pipeline — All Stages Verified

| Stage | Implementation | Test Coverage |
|-------|---------------|---------------|
| Quote parsing (V4 + V5/TDX 1.5) | `platforms::tdx::verify::parse_tdx_quote` | Fixture-backed: header fields, body parsing, truncation, tamper detection |
| ECDSA P-256 quote signature | `verify::verify_quote_signature` | Both V4 and V5 real quotes verified, tamper detection confirmed |
| PCK certificate chain (3-cert) | `dcap::verify_pck_cert_chain` | Leaf → Intermediate → Intel Root CA, hardcoded trust anchor |
| QE report binding | `dcap::verify_qe_report_binding` | SHA-256(attest_key \|\| auth_data) checked against QE report_data |
| QE report ECDSA signature | `dcap::verify_qe_report_signature` | PCK leaf key verifies QE report body |
| FMSPC extraction from PCK cert | `dcap::extract_fmspc_from_pck` | ASN.1 SGX extensions OID 1.2.840.113741.1.13.1.4 |
| TCB status evaluation | `dcap::evaluate_tcb_status` | Two-pass: SGX component match → TDX component match |
| TCB Info signature verification | `dcap::verify_tcb_info_signature` | RawValue preserves Intel-signed JSON bytes |
| QE Identity verification | `dcap::verify_qe_identity` | MRSIGNER, ISVPRODID, masked MISCSELECT/ATTRIBUTES, ISVSVN |
| CRL revocation (leaf + intermediate) | `dcap::check_cert_revocation` + `check_intermediate_ca_revocation` | DER CRL parsing, serial number lookup |
| Signing cert chain (TCB/QE Identity) | `dcap::verify_signing_cert_chain` | 2-cert chain to Intel Root CA |
| Certificate validity periods | `dcap::verify_cert_validity_period` | NotBefore/NotAfter checked via x509-parser |
| Debug policy enforcement | `verify::verify_evidence` | td_attributes bit 0 checked, `allow_debug` param |
| report_data binding | `verify::verify_evidence` | Constant-time comparison, padding to 64 bytes |
| MRCONFIGID binding | `verify::verify_evidence` | Constant-time comparison, padding to 48 bytes |
| **CCEL event log replay** | `ccel::verify_ccel_against_rtmrs` | **Replayed RTMRs match live hardware exactly** |
| Collateral fetching (Intel PCS v4) | `collateral::DefaultTdxCollateralProvider` | Live test against api.trustedservices.intel.com |

## Live Intel PCS v4 Test Results

**V4 Quote** (debug TD, from real hardware):
```
signature_valid: true
collateral_verified: true
report_data_match: Some(true)
tcb_status: OutOfDate
fmspc: 50806f000000
advisory_ids: ["INTEL-SA-00837", "INTEL-SA-00960", "INTEL-SA-00982",
               "INTEL-SA-00986", "INTEL-SA-01079", "INTEL-SA-01103",
               "INTEL-SA-01111"]
collateral_expired: false
```

**V5 Quote** (non-debug TD, TDX 1.5): DCAP chain + signature valid. TCB evaluation fails (`no matching SGX TCB level found`) because the fixture's PCK cert has old SVNs that predate current Intel TCB Info levels. This is expected for old fixtures — the verification pipeline correctly identifies the mismatch.

## Live Hardware Test Results

Booted a TDX VM on tdx-host-1 (Intel Xeon Gold 6526Y / Emerald Rapids, QEMU 10.1.0, kernel 6.17.0-19-generic). Captured TDREPORT (1024 bytes) and CCEL (65536 bytes) from inside the TD guest.

**CCEL replay verification**: All four RTMRs replayed from the event log match the hardware TDREPORT values exactly.

```
MRTD:    eea8b6a814569a52bd1e12f6b869bb2d...
RTMR[0]: 5aca07b1e885e17d1aeaf9d94edb2674... (firmware config)
RTMR[1]: 7fc19ed7b5726f078d331c4125a5d466... (OS loader)
RTMR[2]: 4070333e094dec303a5034cc332c9697... (OS data)
RTMR[3]: 000000000000000000000000000000000... (unused)
```

## What Was Built / Fixed

### New: CCEL Event Log Replay (`src/platforms/tdx/ccel.rs`)

The verify path had a TODO: "CC eventlog present but replay verification not yet implemented". Now implemented:

- `parse_ccel()` — TCG2 event log parser. Handles the Spec ID Event header, iterates TCG_PCR_EVENT2 structures, extracts SHA-384 digests. Gracefully handles trailing padding in the 64KB ACPI CCEL table (breaks on invalid digest counts or unknown algorithms instead of erroring, since the ACPI table is zero-padded beyond actual event data).

- `replay_rtmrs()` — Replays events from zero-initialized RTMRs using `RTMR_new = SHA384(RTMR_old || event_digest)`. MR index 1-4 maps to RTMR[0-3].

- `verify_ccel_against_rtmrs()` — End-to-end: parse CCEL, replay, constant-time compare against quote RTMRs. Wired into `verify_evidence()` so CCEL verification is automatic when `cc_eventlog` is present in the evidence.

### Fix: CCEL parser padding handling

Initial parser errored on digest_count=0xFFFFFFFF at offset 0x848 — this was the boundary between real event data and zero-padded remainder of the 64KB ACPI table. Fixed by treating unreasonable digest counts and unknown algorithm IDs as end-of-data signals (break) rather than hard errors.

### New: Live DCAP integration test (`tests/live_dcap.rs`)

Integration test that fetches real collateral from Intel PCS v4 (TCB Info, QE Identity, CRLs, signing chains) and runs full DCAP verification. Validates: signature, cert chain, QE binding, TCB evaluation, report_data binding.

### New: Bare-metal TDX capture fixture (`tests/capture_fixture.rs`)

Added `capture_tdx_evidence_fixture` test alongside existing Azure tests. Uses ConfigFS TSM to generate evidence, saves as JSON fixture, verifies both with and without collateral.

### New: Live hardware test data

- `test_data/tdx_tdreport_live.bin` — 1024-byte TDREPORT from this host's TDX VM
- `test_data/tdx_ccel_live.bin` — 65536-byte CCEL event log from the same boot

## Architecture

### Source Files

```
src/
├── lib.rs                    — Public API: Verifier, verify(), attest(), detect()
├── types.rs                  — PlatformType, VerifyParams, VerificationResult, Claims
├── error.rs                  — AttestationError enum
├── collateral.rs             — CertProvider + TdxCollateralProvider traits, Intel PCS v4 client
├── utils.rs                  — sha256, sha384, constant_time_eq, pad_report_data
└── platforms/
    ├── tdx/
    │   ├── verify.rs         — parse_tdx_quote, verify_quote_signature, verify_evidence
    │   ├── dcap.rs           — Full DCAP chain: PCK chain, QE report, TCB eval, QE identity, CRL
    │   ├── ccel.rs           — CCEL parsing + RTMR replay + integrity verification
    │   ├── claims.rs         — TDX claim extraction (MRTD, RTMRs, attributes)
    │   ├── evidence.rs       — TdxEvidence struct (quote + optional CCEL)
    │   └── attest.rs         — Evidence generation (Linux-only: ConfigFS TSM / /dev/tdx_guest)
    ├── snp/                  — AMD SEV-SNP (Milan/Genoa/Turin)
    ├── az_snp/               — Azure SEV-SNP (vTPM)
    ├── az_tdx/               — Azure TDX (vTPM)
    ├── gcp_snp/              — GCP SEV-SNP
    └── gcp_tdx/              — GCP TDX
```

### Key Design Decisions

1. **Pure Rust crypto**: `p256` (RustCrypto) for ECDSA P-256, `x509-parser` + `x509-cert` for certificates, `sha2` for hashing. No OpenSSL, no Intel SGX SDK, no C dependencies. Works on any platform including WASM.

2. **Intel Root CA trust anchor**: Hardcoded as `INTEL_SGX_ROOT_CA_PUB_DER` (uncompressed SEC1 P-256 point, 65 bytes). Every verification chain terminates here.

3. **RawValue for signed JSON**: TCB Info and QE Identity JSON envelopes use `serde_json::RawValue` for the signed payload, preventing `serde_json` from reordering keys (BTreeMap) and breaking Intel's signature.

4. **Pluggable providers**: `CertProvider` and `TdxCollateralProvider` traits allow custom implementations (Redis cache, offline bundles, PCCS proxy). Default impls fetch from AMD KDS / Intel PCS v4 with 1-hour in-memory caching.

5. **WASM compatibility**: Verification path has zero OS-specific dependencies. Guest-side attestation (`attest` feature) requires Linux. Provider impls use `reqwest` with `rustls-tls` (no OpenSSL).

6. **Evidence envelope**: Self-describing JSON envelope with `platform` tag enables auto-dispatch to the correct verifier. One `verify()` call handles all platforms.

## Dependencies (TDX feature)

| Crate | Purpose |
|-------|---------|
| `p256` | ECDSA P-256 signature verification (Intel DCAP) |
| `p384` | ECDSA P-384 (SNP) |
| `ecdsa` | Signature trait + hazmat PrehashVerifier |
| `x509-parser` | X.509 cert parsing, CRL parsing, SGX extension extraction |
| `x509-cert` | DER-level cert decoding for TBS extraction |
| `sha2` | SHA-256 (DCAP) + SHA-384 (CCEL replay, quote body) |
| `scroll` | Binary parsing for quote structures |
| `reqwest` + `tokio` | HTTP client for Intel PCS v4 (native only) |
| `subtle` | Constant-time comparisons for security-sensitive fields |
| `chrono` | TCB Info expiry checking |

## Remaining Work

- [ ] Install QGS on tdx-host-1 to enable full TDX Quote generation from live VMs (currently only TDREPORT + CCEL)
- [ ] Capture a fresh V4 quote from this hardware (current V4 fixture is from older hardware with debug bit set)
- [ ] WASM build verification (`cargo build --target wasm32-unknown-unknown --features tdx --no-default-features`)
- [ ] Benchmark: quote verification latency (target: <10ms)
- [ ] CLI binary (`attestation-cli`): verify subcommand for raw quote files
- [ ] Consider adding CCEL event enumeration to Claims (expose individual events to policy engines)
