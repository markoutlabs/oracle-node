#!/usr/bin/env bash
# End to end on a local replica: registry canister -> node -> SDK client,
# through a key rotation and a node restart. The M5.5 exit criterion.
#
# Needs: dfx, the wasm32-unknown-unknown target, python3, and internet access
# for the venue connections. Uses a throwaway dfx identity, never your default.
#
#   scripts/e2e-dfx.sh                # start a clean replica, run, stop it
#   KEEP_REPLICA=1 scripts/e2e-dfx.sh # leave the replica and the node running
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
IDENTITY=${E2E_IDENTITY:-oracle-e2e}
DIR=e2e
NODE_ID=oracle-e2e-1
GATEWAY=http://127.0.0.1:4943
CLIENT=./target/debug/examples/subscribe
NODE=./target/debug/oracle-node

say() { printf '\n== %s\n' "$*"; }
die() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

cleanup() {
  pkill -f "oracle-node start $DIR/node1/config.toml" >/dev/null 2>&1 || true
  if [ -z "${KEEP_REPLICA:-}" ]; then dfx stop >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

# `dfx canister call --output json` prints the Candid value as JSON. A variant
# comes out as {"Ok": ...}; a plain value as itself or a one-element list.
json_value() { python3 -c 'import sys,json
d=json.load(sys.stdin)
d=d[0] if isinstance(d,list) else d
print(d["Ok"] if isinstance(d,dict) and "Ok" in d else d)'; }

# Pulls one counter out of the client example's final ClientStats line.
stat() { grep -o "$1: [0-9]*" "$2" | tail -1 | grep -o '[0-9]*$'; }

say "build"
cargo build -q -p oracle-node --bin oracle-node
cargo build -q -p oracle-client --example subscribe

say "replica"
dfx identity list 2>/dev/null | grep -qx "$IDENTITY" \
  || dfx identity new "$IDENTITY" --storage-mode plaintext >/dev/null
if ! dfx ping >/dev/null 2>&1; then
  dfx start --background --clean >/dev/null 2>&1
fi
dfx deploy oracle_registry --identity "$IDENTITY" --argument \
  '(record { key_name = "dfx_test_key"; rotation_window_secs = 60 : nat64; heartbeat_secs = 86400 : nat64; min_nodes = 1 : nat16; recommended = 3 : nat16 })' \
  >/dev/null 2>&1
CANISTER=$(dfx canister id oracle_registry)
URL="$GATEWAY/registry.json?canisterId=$CANISTER"
GOV=$(dfx canister call oracle_registry refresh_governance_key --identity "$IDENTITY" --output json | json_value)
echo "canister $CANISTER"
echo "governance $GOV"

say "node identity, submitted and approved"
rm -rf "$DIR" && mkdir -p "$DIR"
$NODE init --out "$DIR/node1" --node-id "$NODE_ID" --operator e2e \
  --endpoint ws://127.0.0.1:8791/v1/ws --canister "$CANISTER" > "$DIR/init.out"
eval "$(grep '^dfx canister call' "$DIR/init.out") --identity $IDENTITY" >/dev/null
dfx canister call oracle_registry approve_entry "(\"$NODE_ID\")" --identity "$IDENTITY" >/dev/null
python3 - "$DIR/node1/config.toml" "$URL" "$GOV" <<'PY'
import sys, re, pathlib
path, url, gov = sys.argv[1:]
p = pathlib.Path(path); s = p.read_text()
s = re.sub(r'^path = ".*"$', f'url = "{url}"', s, count=1, flags=re.M)
s = re.sub(r'^governance_address = ".*"$', f'governance_address = "{gov}"', s, count=1, flags=re.M)
p.write_text(s)
PY
echo "registry v$(dfx canister call oracle_registry get_version --identity "$IDENTITY" --output json | json_value)"

start_node() {
  (RUST_LOG=info nohup $NODE start "$DIR/node1/config.toml" > "$1" 2>&1 &)
  for _ in $(seq 1 30); do
    grep -q "serving subscribers" "$1" 2>/dev/null && return 0
    grep -qi "error" "$1" 2>/dev/null && { cat "$1"; die "node did not start"; }
    sleep 1
  done
  die "node did not start in time"
}

say "node starts against the canister"
start_node "$DIR/node1.log"
echo "signer $(grep -o "0x[0-9a-f]\{40\}" "$DIR/node1.log" | head -1)"

say "client baseline, 15s"
$CLIENT "$URL" "$GOV" CRYPTO.BTC/USDT --seconds 15 --every 1000 > "$DIR/client-baseline.log" 2>&1 \
  || { cat "$DIR/client-baseline.log"; die "baseline client failed"; }
tail -1 "$DIR/client-baseline.log"
[ "$(stat accepted "$DIR/client-baseline.log")" -gt 0 ] || die "no updates verified"
[ "$(stat untrusted "$DIR/client-baseline.log")" -eq 0 ] || die "untrusted frames in baseline"

say "rotation under a live client, 90s"
$CLIENT "$URL" "$GOV" CRYPTO.BTC/USDT --seconds 90 --every 1000 > "$DIR/client-rotation.log" 2>&1 &
CLIENT_PID=$!
sleep 10
$NODE rotate --dir "$DIR/node1" --canister "$CANISTER" > "$DIR/rotate.out"
grep -o "new signing  0x[0-9a-f]*" "$DIR/rotate.out" || true
eval "$(grep 'dfx canister call' "$DIR/rotate.out" | sed 's/^ *//') --identity $IDENTITY" >/dev/null
echo "registry v$(dfx canister call oracle_registry get_version --identity "$IDENTITY" --output json | json_value)"
mv "$DIR/node1/signing.key.next" "$DIR/node1/signing.key"
pkill -f "oracle-node start $DIR/node1/config.toml"
sleep 1
start_node "$DIR/node1b.log"
echo "signer $(grep -o "0x[0-9a-f]\{40\}" "$DIR/node1b.log" | head -1)"
wait "$CLIENT_PID" || { cat "$DIR/client-rotation.log"; die "rotation client failed"; }
grep -- "--- adopted registry" "$DIR/client-rotation.log" || die "client never adopted the new registry"
tail -1 "$DIR/client-rotation.log"
[ "$(stat refreshes "$DIR/client-rotation.log")" -eq 1 ] || die "expected exactly one registry refresh"
[ "$(stat untrusted "$DIR/client-rotation.log")" -eq 0 ] || die "untrusted frames during rotation"
[ "$(stat replayed "$DIR/client-rotation.log")" -eq 0 ] || die "replays after the restart: seq did not survive"
[ "$(stat refresh_failures "$DIR/client-rotation.log")" -eq 0 ] || die "a refresh failed"

say "key history on the canister"
dfx canister call oracle_registry get_key_history "(\"$NODE_ID\")" --identity "$IDENTITY" --output json \
  | json_value | python3 -c 'import sys,json
for e in json.loads(sys.stdin.read()):
    print("gen", e["generation"], e["cert"]["address"], "retired_at", e["retired_at"])'

say "PASS"
