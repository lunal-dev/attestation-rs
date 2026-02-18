#!/usr/bin/env bash
set -euo pipefail

BIN="./target/release/examples/az_snp_attest_cli"
RUNS=${1:-5}

if [[ ! -f "$BIN" ]]; then
    echo "Building release binary..."
    cargo build --release --features "all-platforms,attest" --example az_snp_attest_cli
fi

echo "=== Azure SNP Attestation Timing ($RUNS runs) ==="
echo ""

echo "--- WITH custom data ---"
for i in $(seq 1 "$RUNS"); do
    echo "  run $i:"
    time "$BIN" "my-custom-nonce-data-$i" > /dev/null
    echo ""
done

echo "--- WITHOUT custom data (empty) ---"
for i in $(seq 1 "$RUNS"); do
    echo "  run $i:"
    time "$BIN" > /dev/null
    echo ""
done
