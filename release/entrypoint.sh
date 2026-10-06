#!/usr/bin/env bash
# Runs inside the release image: builds the canister wasm and the node binary,
# then writes them and their sha256 sums to /out.
set -euo pipefail

# Build paths would otherwise end up in the artifacts and differ per machine.
export RUSTFLAGS="--remap-path-prefix /src=/build --remap-path-prefix ${CARGO_HOME}=/cargo --remap-path-prefix ${RUSTUP_HOME}=/rustup"
export CFLAGS="-ffile-prefix-map=/src=/build -ffile-prefix-map=${CARGO_HOME}=/cargo"

make --no-print-directory canister node

cp target/wasm32-unknown-unknown/release/oracle_registry_canister.wasm /out/
cp target/release/oracle-node /out/oracle-node-linux-amd64
cd /out
sha256sum oracle_registry_canister.wasm oracle-node-linux-amd64 > SHA256SUMS
cat SHA256SUMS
