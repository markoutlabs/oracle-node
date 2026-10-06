#!/usr/bin/env bash
# The icp-cli path on a local network, which the Rust end-to-end test
# (crates/oracle-node/tests/e2e.rs) does not touch: icp.yaml and its build
# step, `icp deploy`, `make governance`, and the `icp canister call` lines that
# `oracle-node init` and `rotate` print for governance. No node runs and no
# venue is contacted.
#
# Needs: icp-cli, ic-wasm, candid-extractor, the wasm32-unknown-unknown target,
# and python3. Uses a throwaway icp identity, never your default.
#
#   scripts/smoke.sh                 # start the local network if needed, run, stop it
#   KEEP_NETWORK=1 scripts/smoke.sh  # leave the network running
set -euo pipefail

cd "$(dirname "$0")/.."
IDENTITY=${SMOKE_IDENTITY:-oracle-e2e}
DIR=target/smoke
NODE=./target/debug/oracle-node

say() { printf '\n== %s\n' "$*"; }
die() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

cleanup() {
  if [ -z "${KEEP_NETWORK:-}" ]; then icp network stop >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

# Runs the `icp canister call` a command printed, as governance and exactly as
# printed, and checks the version it publishes.
run_printed() { # file, version
  local line
  line=$(grep -o 'icp canister call .*' "$1") || die "$1 prints no icp canister call"
  eval "$line --identity $IDENTITY" | grep -q "Ok = $2 " || die "$line did not publish v$2"
}

say "build"
cargo build -q -p oracle-node --bin oracle-node

say "deploy with icp.yaml's init args"
icp identity list 2>/dev/null | grep -qw "$IDENTITY" \
  || icp identity new "$IDENTITY" --storage plaintext --output-seed /dev/null --quiet >/dev/null
icp network status >/dev/null 2>&1 || icp network start -d >/dev/null
# Reinstall: a kept network may hold state from an older build.
icp deploy oracle_registry --mode reinstall --yes --identity "$IDENTITY" >/dev/null 2>&1
GOVERNANCE=$(make --no-print-directory governance IDENTITY="$IDENTITY")
CANISTER=$(awk '/^canister/ {print $2}' <<<"$GOVERNANCE")
GOV=$(awk '/^governance/ {print $2}' <<<"$GOVERNANCE")
[ -n "$CANISTER" ] && [ -n "$GOV" ] || die "make governance printed: $GOVERNANCE"
read -r GATEWAY ROOT_KEY < <(icp network status --json \
  | python3 -c 'import sys,json; s=json.load(sys.stdin); print(s["gateway_url"].rstrip("/"), s["root_key"])')
echo "$GOVERNANCE"

say "init prints add_node"
rm -rf "$DIR" && mkdir -p "$DIR"
echo "smoke" > "$DIR/passphrase"
$NODE init --out "$DIR/node" --canister "$CANISTER" \
  --gateway "$GATEWAY" --root-key "$ROOT_KEY" --governance "$GOV" \
  --passphrase-file "$DIR/passphrase" > "$DIR/init.out"
run_printed "$DIR/init.out" 1
ADDRESS=$(python3 -c 'import sys,json; print(json.load(open(sys.argv[1]))["address"])' "$DIR/node/node-entry.json")
curl -sf "$GATEWAY/registry.json?canisterId=$CANISTER" | grep -qi "$ADDRESS" \
  || die "the gateway does not serve a registry that lists $ADDRESS"
echo "registry v1 lists $ADDRESS"

say "rotate prints replace_node"
$NODE rotate --dir "$DIR/node" > "$DIR/rotate.out"
run_printed "$DIR/rotate.out" 2
echo "registry v2"

say "PASS"
