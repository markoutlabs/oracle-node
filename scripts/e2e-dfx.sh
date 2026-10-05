#!/usr/bin/env bash
# End to end on a local replica: registry canister -> node -> SDK client over
# the authenticated, encrypted transport (SPEC §6.1), through a node key rotation
# (`replace_node`) and restart, a client revocation, and a client expiry.
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
GATEWAY=http://127.0.0.1:4943
CLIENT=./target/debug/examples/subscribe
CLIENT_KEY=./target/debug/examples/client_key
NODE=./target/debug/oracle-node
HEALTH=http://127.0.0.1:8791/v2/health

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

# The node log without its ANSI colours, so fields can be matched.
plain() { sed $'s/\x1b\\[[0-9;]*m//g' "$1"; }

# Pulls one counter out of the client example's final ClientStats line.
stat() { grep -o "$1: [0-9]*" "$2" | tail -1 | grep -o '[0-9]*$'; }

say "build"
cargo build -q -p oracle-node --bin oracle-node
cargo build -q -p oracle-client --example subscribe --example client_key

say "replica"
dfx identity list 2>/dev/null | grep -qx "$IDENTITY" \
  || dfx identity new "$IDENTITY" --storage-mode plaintext >/dev/null
if ! dfx ping >/dev/null 2>&1; then
  dfx start --background --clean >/dev/null 2>&1
fi
# Reinstall: a kept replica may hold state from an older build.
dfx deploy oracle_registry --identity "$IDENTITY" --mode reinstall --yes --argument \
  '(record { key_name = "dfx_test_key"; min_nodes = 1 : nat16; recommended = 3 : nat16; epoch_secs = opt (10 : nat64) })' \
  >/dev/null 2>&1
CANISTER=$(dfx canister id oracle_registry)
URL="$GATEWAY/registry.json?canisterId=$CANISTER"
CLIENTS_URL="$GATEWAY/clients.json?canisterId=$CANISTER"
GOV=$(dfx canister call oracle_registry refresh_governance_key --identity "$IDENTITY" --output json | json_value)
# The node and the client check each fetched document's IC certificate
# against this replica's root key.
ROOT_KEY=$(dfx ping | python3 -c 'import sys,json; print(bytes(json.load(sys.stdin)["root_key"]).hex())')
CERT_ARGS=(--canister-id "$CANISTER" --root-key "$ROOT_KEY")
echo "canister $CANISTER"
echo "governance $GOV"

say "node key, added by governance"
rm -rf "$DIR" && mkdir -p "$DIR"
# The key is encrypted at rest; the node opens it with this passphrase file.
python3 -c 'import secrets; print(secrets.token_hex(16))' > "$DIR/passphrase"
chmod 600 "$DIR/passphrase"
$NODE init --out "$DIR/node1" --operator e2e \
  --endpoint ws://127.0.0.1:8791/v2/ws --canister "$CANISTER" \
  --passphrase-file "$DIR/passphrase" > "$DIR/init.out"
# The e2e identity is the controller, so it plays governance for both calls.
eval "$(grep '^dfx canister call' "$DIR/init.out") --identity $IDENTITY" >/dev/null
python3 - "$DIR/node1/config.toml" "$URL" "$GOV" "$CLIENTS_URL" "$CANISTER" "$ROOT_KEY" <<'PY'
import sys, re, pathlib
path, url, gov, clients, canister, root_key = sys.argv[1:]
p = pathlib.Path(path); s = p.read_text()
s = re.sub(r'^path = ".*"$', f'url = "{url}"', s, count=1, flags=re.M)
s = re.sub(r'^governance_address = ".*"$', f'governance_address = "{gov}"', s, count=1, flags=re.M)
assert 'canister_id = "<canister-id>"' in s, "the starter config has no canister_id"
s = s.replace('canister_id = "<canister-id>"',
              f'canister_id = "{canister}"\nroot_key = "{root_key}"')
s = s.replace('url = "https://<canister-id>.raw.icp0.io/clients.json"',
              f'url = "{clients}"\npoll_secs = 5')
assert '[clients]\nurl' in s, "the starter config has no [clients] block"
p.write_text(s)
PY
echo "registry v$(dfx canister call oracle_registry get_version --identity "$IDENTITY" --output json | json_value)"

say "client key, added by governance"
# A client is the address of its key. The node logs it in lowercase.
address_of() { grep -o '^address 0x[0-9a-fA-F]*' "$DIR/$1.out" | cut -d' ' -f2; }
add_client() { # name, expires_at
  $CLIENT_KEY --out "$DIR/$1.key" > "$DIR/$1.out"
  dfx canister call oracle_registry add_client "(\"$(address_of "$1")\", $2 : nat64)" \
    --identity "$IDENTITY" --output json | json_value
}
echo "client list v$(add_client c-1 $(( $(date +%s) + 86400 )))"
C1=$(address_of c-1)
echo "client $C1"

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
echo "node $(grep -o "0x[0-9a-fA-F]\{40\}" "$DIR/node1.log" | head -1)"

say "client baseline, 15s"
$CLIENT "$URL" "$GOV" CRYPTO.BTC/USDT "${CERT_ARGS[@]}" --seconds 15 --every 1000 \
  --client-key "$DIR/c-1.key" > "$DIR/client-baseline.log" 2>&1 \
  || { cat "$DIR/client-baseline.log"; die "baseline client failed"; }
tail -1 "$DIR/client-baseline.log"
[ "$(stat accepted "$DIR/client-baseline.log")" -gt 0 ] || die "no updates verified"
[ "$(stat untrusted "$DIR/client-baseline.log")" -eq 0 ] || die "untrusted frames in baseline"

say "rotation under a live client, 90s"
$CLIENT "$URL" "$GOV" CRYPTO.BTC/USDT "${CERT_ARGS[@]}" --seconds 90 --every 1000 \
  --client-key "$DIR/c-1.key" > "$DIR/client-rotation.log" 2>&1 &
CLIENT_PID=$!
sleep 10
$NODE rotate --dir "$DIR/node1" --canister "$CANISTER" > "$DIR/rotate.out"
OLD=$(grep -o 'old address  0x[0-9a-fA-F]*' "$DIR/rotate.out" | awk '{print $3}')
NEW=$(grep -o 'new address  0x[0-9a-fA-F]*' "$DIR/rotate.out" | awk '{print $3}')
[ -n "$OLD" ] && [ -n "$NEW" ] || { cat "$DIR/rotate.out"; die "rotate printed no addresses"; }
echo "replace $OLD -> $NEW"
eval "$(grep 'dfx canister call' "$DIR/rotate.out" | sed 's/^ *//') --identity $IDENTITY" >/dev/null
echo "registry v$(dfx canister call oracle_registry get_version --identity "$IDENTITY" --output json | json_value)"
mv "$DIR/node1/signing.key.next" "$DIR/node1/signing.key"
pkill -f "oracle-node start $DIR/node1/config.toml"
sleep 1
start_node "$DIR/node1b.log"
echo "node $(grep -o "0x[0-9a-fA-F]\{40\}" "$DIR/node1b.log" | head -1)"
wait "$CLIENT_PID" || { cat "$DIR/client-rotation.log"; die "rotation client failed"; }
grep -- "--- adopted registry" "$DIR/client-rotation.log" || die "client never adopted the new registry"
tail -1 "$DIR/client-rotation.log"
# A scheduled poll can adopt the new key first, so zero refreshes is fine too.
[ "$(stat refreshes "$DIR/client-rotation.log")" -le 1 ] || die "a rotation cost more than one registry refresh"
[ "$(stat untrusted "$DIR/client-rotation.log")" -eq 0 ] || die "untrusted frames during rotation"
[ "$(stat replayed "$DIR/client-rotation.log")" -eq 0 ] || die "replays after the restart: seq did not survive"
[ "$(stat refresh_failures "$DIR/client-rotation.log")" -eq 0 ] || die "a refresh failed"

say "revocation: governance removes c-1 under a live session"
$CLIENT "$URL" "$GOV" CRYPTO.BTC/USDT "${CERT_ARGS[@]}" --seconds 30 --every 1000 \
  --client-key "$DIR/c-1.key" > "$DIR/client-revoked.log" 2>&1 &
CLIENT_PID=$!
sleep 8
echo "client list v$(dfx canister call oracle_registry remove_client "(\"$C1\")" --identity "$IDENTITY" --output json | json_value)"
sleep 12
plain "$DIR/node1b.log" | grep -qi "client session closed client=\"\?$C1\"\? reason=Revoked" || die "the node did not close the revoked session"
grep -q "broadcast keys rotated" "$DIR/node1b.log" || die "the node did not rotate its broadcast key"
curl -s "$HEALTH" | grep -q '"subscribers":0' || die "a revoked client is still subscribed"
wait "$CLIENT_PID" || true
echo "revoked: session closed, keys rotated, no subscriber left"

say "expiry: c-2 is listed for about 25 s"
echo "client list v$(add_client c-2 $(( $(date +%s) + 25 )))"
C2=$(address_of c-2)
sleep 7
$CLIENT "$URL" "$GOV" CRYPTO.BTC/USDT "${CERT_ARGS[@]}" --seconds 30 --every 1000 \
  --client-key "$DIR/c-2.key" > "$DIR/client-expiry.log" 2>&1 || true
plain "$DIR/node1b.log" | grep -qi "client session closed client=\"\?$C2\"\? reason=Expired" || die "the session outlived its deadline"
[ "$(stat accepted "$DIR/client-expiry.log")" -gt 0 ] || die "c-2 never received a price"
echo "expired: c-2 received prices, then the node closed it at its deadline"

say "node listings on the canister"
listing() { dfx canister call oracle_registry get_node_listing "(\"$1\")" --identity "$IDENTITY" --output json | json_value; }
OLD_LISTING=$(listing "$OLD")
NEW_LISTING=$(listing "$NEW")
echo "old $OLD_LISTING"
echo "new $NEW_LISTING"
echo "$OLD_LISTING" | grep -q '"removed_at":[0-9]' || die "the old address is not retired"
echo "$NEW_LISTING" | grep -q '"removed_at":null' || die "the new address is not listed"

say "PASS"
