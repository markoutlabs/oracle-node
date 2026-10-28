#!/usr/bin/env bash
# icp-cli's build step for the registry canister: puts the wasm to install at
# $ICP_WASM_OUTPUT_PATH.
#
# Mainnet gets the reproducible build from `make release`. REPRODUCIBLE=0 lets
# it take a wasm built on this machine, as every other environment does.
set -euo pipefail

cd "$(dirname "$0")/.."
RELEASE_WASM=target/release-artifacts/oracle_registry_canister.wasm
LOCAL_WASM=target/wasm32-unknown-unknown/release/oracle_registry_canister.wasm

if [ "${ICP_CLI_ENVIRONMENT:-local}" = ic ] && [ "${REPRODUCIBLE:-1}" != 0 ]; then
  if [ ! -f "$RELEASE_WASM" ]; then
    echo "no release build at $RELEASE_WASM: run \`make release\` first" >&2
    exit 1
  fi
  # The check of release/publish.sh: a build from another commit, or from a
  # dirty tree, is not the code that mainnet would run.
  if [ "$(cat target/release-artifacts/.commit 2>/dev/null)" != "$(git rev-parse HEAD)" ]; then
    echo "the release build is not from HEAD on a clean tree: run \`make release\`" >&2
    exit 1
  fi
  cp "$RELEASE_WASM" "$ICP_WASM_OUTPUT_PATH"
else
  make --no-print-directory canister >&2
  cp "$LOCAL_WASM" "$ICP_WASM_OUTPUT_PATH"
fi
