#!/usr/bin/env bash
# icp-cli's build step for the registry canister: puts the wasm to install at
# $ICP_WASM_OUTPUT_PATH.
#
# Mainnet gets only the reproducible build from `make release`, never a wasm
# built on this machine. Every other environment builds here.
set -euo pipefail

cd "$(dirname "$0")/.."
RELEASE_WASM=target/release-artifacts/oracle_registry_canister.wasm
LOCAL_WASM=target/wasm32-unknown-unknown/release/oracle_registry_canister.wasm

if [ "${ICP_CLI_ENVIRONMENT:-local}" = ic ]; then
  if [ ! -f "$RELEASE_WASM" ]; then
    echo "no release build at $RELEASE_WASM: run \`make release\` first" >&2
    exit 1
  fi
  cp "$RELEASE_WASM" "$ICP_WASM_OUTPUT_PATH"
else
  make --no-print-directory canister >&2
  cp "$LOCAL_WASM" "$ICP_WASM_OUTPUT_PATH"
fi
