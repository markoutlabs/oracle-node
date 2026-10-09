#!/usr/bin/env bash
# `make release`: builds the release artifacts in the pinned image and writes
# them to target/release-artifacts/:
#
#   oracle_registry_canister.wasm   the canister, with its candid:service baked in
#   oracle-node-linux-{amd64,arm64}   the node binary for Linux servers
#   SHA256SUMS                      compare these with anyone else's build
#
# The container keeps its own target dir (target/docker/), so the host build
# is left alone.
set -euo pipefail

cd "$(dirname "$0")/.."
IMAGE=price-oracle-release

docker build --platform linux/amd64 -f release/Dockerfile -t "$IMAGE" .
mkdir -p target/docker target/release-artifacts
rm -f target/release-artifacts/*
# `make publish` uploads the artifacts only for the commit they came from.
commit="$(git rev-parse HEAD)"
[ -z "$(git status --porcelain)" ] || commit="$commit-dirty"
echo "$commit" > target/release-artifacts/.commit
docker run --rm --platform linux/amd64 \
  -v "$(pwd)/target/docker:/src/target" \
  -v "$(pwd)/target/release-artifacts:/out" \
  "$IMAGE"
