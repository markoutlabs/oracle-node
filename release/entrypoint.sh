#!/usr/bin/env bash
# Runs inside the release image: builds the canister wasm, and the node and proxy
# binaries for Linux amd64 and arm64, then writes them and their sha256 sums to /out.
set -euo pipefail

# Build paths would otherwise end up in the artifacts and differ per machine.
export RUSTFLAGS="--remap-path-prefix /src=/build --remap-path-prefix ${CARGO_HOME}=/cargo --remap-path-prefix ${RUSTUP_HOME}=/rustup"
export CFLAGS="-ffile-prefix-map=/src=/build -ffile-prefix-map=${CARGO_HOME}=/cargo"

# The oldest glibc the Linux binaries need. 2.28 covers Debian 10, Ubuntu 20.04 and RHEL 8.
GLIBC=2.28

make --no-print-directory canister
cp target/wasm32-unknown-unknown/release/oracle_registry_canister.wasm /out/

for arch in amd64 arm64; do
  case "$arch" in
    amd64) triple=x86_64-unknown-linux-gnu ;;
    arm64) triple=aarch64-unknown-linux-gnu ;;
  esac
  # One package per build, so each binary matches a plain `cargo build -p` of it.
  for package in oracle-node oracle-proxy; do
    cargo zigbuild --release --locked --target "$triple.$GLIBC" -p "$package" --bin "$package"
    cp "target/$triple/release/$package" "/out/$package-linux-$arch"
  done
done

cd /out
sha256sum oracle_registry_canister.wasm oracle-node-linux-* oracle-proxy-linux-* > SHA256SUMS
cat SHA256SUMS
