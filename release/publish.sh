#!/usr/bin/env bash
# `make publish`: uploads the `make release` artifacts and the install script as
# the GitHub release v<workspace version>. Build from a clean tree, then tag and
# push that commit first.
set -euo pipefail

cd "$(dirname "$0")/.."
DIR=target/release-artifacts
ASSETS=(oracle_registry_canister.wasm oracle-node-linux-amd64 oracle-node-linux-arm64
  oracle-proxy-linux-amd64 oracle-proxy-linux-arm64 SHA256SUMS)

fail() {
  echo "publish: $*" >&2
  exit 1
}

version="$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)"
tag="v$version"
head="$(git rev-parse HEAD)"

[ -z "$(git status --porcelain)" ] || fail "the tree has changes; commit them and run make release again"
[ "$(cat "$DIR/.commit" 2>/dev/null)" = "$head" ] ||
  fail "the artifacts are not from HEAD ($head); run make release"
[ "$(git rev-parse -q --verify "refs/tags/$tag^{commit}")" = "$head" ] ||
  fail "tag $tag must point at HEAD: git tag $tag && git push origin $tag"
git ls-remote --exit-code --tags origin "refs/tags/$tag" >/dev/null ||
  fail "push the tag first: git push origin $tag"
for asset in "${ASSETS[@]}"; do
  [ -f "$DIR/$asset" ] || fail "$DIR/$asset is missing; run make release"
done
(cd "$DIR" && shasum -a 256 -c SHA256SUMS >/dev/null) || fail "SHA256SUMS does not match the files"

repo="$(gh repo view --json nameWithOwner -q .nameWithOwner)"
notes="$(cat <<NOTES
Install the node, or the web proxy, on Linux (amd64 or arm64, glibc 2.28 or newer):

\`\`\`sh
# The node, then the web proxy, from this release
curl -fsSL https://github.com/$repo/releases/download/$tag/install.sh | sh -s -- node --version $tag
curl -fsSL https://github.com/$repo/releases/download/$tag/install.sh | sh -s -- proxy --version $tag
\`\`\`

The script checks each binary against SHA256SUMS. The build is reproducible: \`make release\`
on commit \`$head\` gives the same sums.

\`\`\`
$(cat "$DIR/SHA256SUMS")
\`\`\`
NOTES
)"

gh release create "$tag" --verify-tag --title "$tag" --notes "$notes" \
  "${ASSETS[@]/#/$DIR/}" release/install.sh
