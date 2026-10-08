#!/usr/bin/env bash
# A local oracle for development: the registry canister on the local network,
# NODES nodes that read the live venues, and oracle-proxy in front of them.
# Nothing on mainnet is touched. It reinstalls the local canister, and it uses
# a throwaway icp identity, never your default.
#
#   scripts/dev-stack.sh            # 3 nodes at quorum 3; Ctrl-C stops everything
#   NODES=1 scripts/dev-stack.sh    # one node, at quorum 1
#   KEEP=1 scripts/dev-stack.sh     # leave the local network running on exit
#
# The proxy serves ws://127.0.0.1:8792/v1/ws, and node N listens on 880N. Each
# node serves every feed in node/all-feeds.toml. Logs and keys are in
# target/dev-stack/.
set -euo pipefail

cd "$(dirname "$0")/.."
IDENTITY=${DEV_IDENTITY:-oracle-e2e}
NODES=${NODES:-3}
PROXY_PORT=${PROXY_PORT:-8792}
# Books cost a signature per change on every node, so only a few by default.
BOOKS=${BOOKS:-"CRYPTO.BTC/USDT CRYPTO.BTC/USD"}
DIR=$(pwd)/target/dev-stack
BIN=$(pwd)/target/release

say() { printf '\n== %s\n' "$*"; }
die() { printf 'dev-stack: %s\n' "$*" >&2; exit 1; }

PIDS=()
NAMES=()
cleanup() {
  for pid in "${PIDS[@]+"${PIDS[@]}"}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  if [ -z "${KEEP:-}" ]; then icp network stop >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

start() { # name, log file, command...
  local name=$1 log=$2
  shift 2
  "$@" >"$log" 2>&1 &
  PIDS+=("$!")
  NAMES+=("$name")
}

# Runs the `icp canister call` that init printed, as governance.
run_printed() { # file
  local line
  line=$(grep -o 'icp canister call .*' "$1") || die "$1 prints no icp canister call"
  eval "$line --identity $IDENTITY" | grep -q "Ok = " || die "$line failed"
}

# A TOML array of strings.
toml_list() {
  local out="" item
  for item in "$@"; do out+="${out:+, }\"$item\""; done
  printf '[%s]' "$out"
}

[[ $NODES =~ ^[1-9]$ ]] || die "NODES must be 1 to 9"

say "build"
cargo build -q --release --locked -p oracle-node --bin oracle-node -p oracle-proxy --bin oracle-proxy

say "registry canister on the local network"
icp identity list 2>/dev/null | grep -qw "$IDENTITY" \
  || icp identity new "$IDENTITY" --storage plaintext --output-seed /dev/null --quiet >/dev/null
icp network status >/dev/null 2>&1 || icp network start -d >/dev/null
icp deploy oracle_registry --mode reinstall --yes --identity "$IDENTITY" >/dev/null 2>&1
GOVERNANCE=$(make --no-print-directory governance IDENTITY="$IDENTITY")
CANISTER=$(awk '/^canister/ {print $2}' <<<"$GOVERNANCE")
GOV=$(awk '/^governance/ {print $2}' <<<"$GOVERNANCE")
[ -n "$CANISTER" ] && [ -n "$GOV" ] || die "make governance printed: $GOVERNANCE"
read -r GATEWAY ROOT_KEY < <(icp network status --json \
  | python3 -c 'import sys,json; s=json.load(sys.stdin); print(s["gateway_url"].rstrip("/"), s["root_key"])')
echo "$GOVERNANCE"

rm -rf "$DIR" && mkdir -p "$DIR"
printf 'dev-stack\n' >"$DIR/passphrase" && chmod 600 "$DIR/passphrase"
FEEDS_AT=$(grep -n '^\[\[feeds\]\]' node/all-feeds.toml | head -n 1 | cut -d: -f1)
SYMBOLS=()
while IFS= read -r symbol; do SYMBOLS+=("$symbol"); done \
  < <(sed -n 's/^symbol = "\(.*\)"$/\1/p' node/all-feeds.toml)

say "$NODES nodes"
for i in $(seq 1 "$NODES"); do
  # Above the proxy's port, so the defaults never collide.
  port=$((8800 + i))
  node="$DIR/node$i"
  "$BIN/oracle-node" init --out "$node" --endpoint "ws://127.0.0.1:$port/v2/ws" \
    --canister "$CANISTER" --gateway "$GATEWAY" --root-key "$ROOT_KEY" --governance "$GOV" \
    --passphrase-file "$DIR/passphrase" >"$DIR/node$i.init.out"
  run_printed "$DIR/node$i.init.out"
  # The starter config serves one feed on every interface; this one serves
  # every feed, on loopback only.
  config="$node/config.toml"
  starter_feeds=$(grep -n '^\[\[feeds\]\]' "$config" | head -n 1 | cut -d: -f1)
  {
    sed -n "1,$((starter_feeds - 1))p" "$config" | sed 's/^listen = "0\.0\.0\.0:/listen = "127.0.0.1:/'
    tail -n +"$FEEDS_AT" node/all-feeds.toml
  } >"$config.new"
  mv "$config.new" "$config"
  echo "node$i  $(python3 -c 'import sys,json; print(json.load(open(sys.argv[1]))["address"])' "$node/node-entry.json")  ws://127.0.0.1:$port/v2/ws"
done

say "the proxy's client key, listed"
key_out=$(scripts/client-key.sh --out "$DIR/proxy.key")
ADDRESS=$(awk '/^address/ {print $2}' <<<"$key_out")
ENV=local scripts/add-client.sh --identity "$IDENTITY" --address "$ADDRESS" \
  --expires $(($(date +%s) + 30 * 86400)) >/dev/null 2>&1 || die "add_client failed"
echo "proxy  $ADDRESS"

if [ "$NODES" -ge 3 ]; then QUORUM=3 LOW=false; else QUORUM=$NODES LOW=true; fi
# shellcheck disable=SC2086 # BOOKS is a space-separated list on purpose.
cat >"$DIR/proxy.toml" <<EOF
listen = "127.0.0.1:$PROXY_PORT"

[upstream]
canister_id = "$CANISTER"
registry_url = "$GATEWAY/registry.json?canisterId=$CANISTER"
root_key = "$ROOT_KEY"
governance = "$GOV"
client_key_file = "$DIR/proxy.key"
quorum = $QUORUM
allow_low_quorum = $LOW

[feeds]
prices = $(toml_list "${SYMBOLS[@]}")
venues = $(toml_list "${SYMBOLS[@]}")
books = $(toml_list $BOOKS)
EOF

say "start"
for i in $(seq 1 "$NODES"); do
  start "node$i" "$DIR/node$i.log" "$BIN/oracle-node" start "$DIR/node$i/config.toml"
done
start proxy "$DIR/proxy.log" "$BIN/oracle-proxy" "$DIR/proxy.toml"

health="http://127.0.0.1:$PROXY_PORT/health"
for _ in $(seq 1 120); do
  curl -sf "$health" | grep -q '"status":"ok"' && break
  sleep 0.5
done
curl -sf "$health" | grep -q '"status":"ok"' || die "the proxy has no price after 60 s; see $DIR/proxy.log"

cat <<EOF

The oracle runs on the local network:
  proxy      ws://127.0.0.1:$PROXY_PORT/v1/ws
  catalog    http://127.0.0.1:$PROXY_PORT/v1/catalog
  nodes      http://127.0.0.1:$PROXY_PORT/v1/nodes
  logs       $DIR/*.log
Stop a node to watch the quorum react: kill <pid> (node pids: ${PIDS[*]:0:$NODES}).
Ctrl-C stops everything.
EOF

# bash 3.2 has no `wait -n`, so check each process now and then.
while true; do
  for index in "${!PIDS[@]}"; do
    if ! kill -0 "${PIDS[$index]}" 2>/dev/null; then
      echo "${NAMES[$index]} stopped; the last lines of its log:" >&2
      tail -n 20 "$DIR/${NAMES[$index]}.log" >&2
      unset 'PIDS[index]' 'NAMES[index]'
    fi
  done
  [ "${#PIDS[@]}" -gt 0 ] || exit 1
  sleep 2
done
