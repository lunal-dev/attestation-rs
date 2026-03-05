#!/usr/bin/env bash
# Test roundtrip of custom report_data through Az SNP attestation + verification.
# Run this on an Azure SNP CVM.
set -euo pipefail

CLI="./target/release/attestation-cli"
CUSTOM_DATA="my-custom-nonce-12345"
CUSTOM_DATA_HEX=$(printf '%s' "$CUSTOM_DATA" | xxd -p | tr -d '\n')

echo "=== Azure SNP Attestation: TPM Nonce Roundtrip Test ==="
echo "Custom data string: $CUSTOM_DATA"
echo "Custom data hex:    $CUSTOM_DATA_HEX"
echo ""

# Build if needed
if [[ ! -f "$CLI" ]]; then
    echo "Building release binary..."
    cargo build --release --features "all-platforms,attest,cli"
fi

# 1. Generate attestation with custom report data
echo "--- Step 1: Generating attestation evidence ---"
EVIDENCE=$("$CLI" attest --report-data "$CUSTOM_DATA")
echo "Evidence generated ($(echo "$EVIDENCE" | wc -c) bytes)"
echo ""

# 2. Verify with expected report data check
echo "--- Step 2: Verifying with --expected-report-data ---"
RESULT=$(echo "$EVIDENCE" | "$CLI" verify --expected-report-data "$CUSTOM_DATA_HEX")
echo "Verification passed"
echo ""

# 3. Extract nonce from verification JSON
echo "--- Step 3: Extracting TPM nonce from verification output ---"
NONCE_HEX=$(echo "$RESULT" | jq -r '.claims.platform_data.tpm.nonce')
echo "Extracted nonce (hex): $NONCE_HEX"
echo ""

# 4. Compare roundtrip
echo "--- Step 4: Roundtrip comparison ---"
echo "Expected hex: $CUSTOM_DATA_HEX"
echo "Got hex:      $NONCE_HEX"

DECODED=$(echo "$NONCE_HEX" | xxd -r -p)
echo "Decoded string: $DECODED"
echo ""

if [[ "$NONCE_HEX" == "$CUSTOM_DATA_HEX" ]]; then
    echo "PASS: TPM nonce roundtrip successful"
    exit 0
else
    echo "FAIL: TPM nonce mismatch"
    exit 1
fi
