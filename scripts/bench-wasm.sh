#!/usr/bin/env bash
set -euo pipefail
# Build and run the rspow-bench-wasm crate under wasmtime.
#
# Env vars (all optional):
#   BITS=7 THREADS=1 REQUIRED=30 SAMPLES=30 WARMUP=1
#
# Usage:
#   ./scripts/bench-wasm.sh           # wasm via wasmtime
#   ./scripts/bench-wasm.sh --native  # native (for comparison)

BITS="${BITS:-7}"
THREADS="${THREADS:-1}"
REQUIRED="${REQUIRED:-30}"
SAMPLES="${SAMPLES:-30}"
WARMUP="${WARMUP:-1}"
export BITS THREADS REQUIRED SAMPLES WARMUP

if [[ "${1:-}" == "--native" ]]; then
    exec cargo run --release -p rspow-bench-wasm
fi

TARGET_DIR="${CARGO_TARGET_DIR:-target}"
cargo build --release --target wasm32-wasip1 -p rspow-bench-wasm

WASM="${TARGET_DIR}/wasm32-wasip1/release/rspow-bench-wasm.wasm"
exec wasmtime \
    --env "BITS=$BITS" \
    --env "THREADS=$THREADS" \
    --env "REQUIRED=$REQUIRED" \
    --env "SAMPLES=$SAMPLES" \
    --env "WARMUP=$WARMUP" \
    "$WASM"
