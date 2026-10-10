#!/usr/bin/env bash
# A local oracle for development: the registry canister on the local network,
# and NODES nodes that read the live venues. Nothing on mainnet is touched. It
# reinstalls the local canister, and it uses a throwaway icp identity, never
# your default.
#
#   scripts/dev-stack.sh            # 3 nodes; Ctrl-C stops them and the network
#   NODES=1 scripts/dev-stack.sh    # one node
#   KEEP=1 scripts/dev-stack.sh     # leave the local network running on exit
#   ASSETS=1 scripts/dev-stack.sh   # also the feeds of node/assets.toml (scripts/asset-feeds.py)
#
# Node N listens on 880N and serves every feed in node/all-feeds.toml. One
# client key is listed, for a local SDK client. When the nodes serve, the
# script writes target/dev-stack/stack.env: the canister, the gateway, the
# governance address, that key and the feeds. The oracle-proxy repo's
# scripts/dev.sh reads it and starts the proxy. Logs and keys are in
# target/dev-stack/.
set -euo pipefail

cd "$(dirname "$0")/.."
IDENTITY=${DEV_IDENTITY:-oracle-e2e}
NODES=${NODES:-3}
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

[[ $NODES =~ ^[1-9]$ ]] || die "NODES must be 1 to 9"

say "build"
cargo build -q --release --locked -p oracle-node --bin oracle-node

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
# node/assets.toml holds feeds only, so it follows the playground's feeds as it is.
EXTRA_FEEDS=()
[ -z "${ASSETS:-}" ] || EXTRA_FEEDS=(node/assets.toml)
SYMBOLS=()
while IFS= read -r symbol; do SYMBOLS+=("$symbol"); done \
  < <(sed -n 's/^symbol = "\(.*\)"$/\1/p' node/all-feeds.toml ${EXTRA_FEEDS[@]+"${EXTRA_FEEDS[@]}"})

say "$NODES nodes"
for i in $(seq 1 "$NODES"); do
  # Above oracle-proxy's default port, 8792, so the two never collide.
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
    # A client of every channel of ~250 feeds can have more than 512 waiting.
    sed -n "1,$((starter_feeds - 1))p" "$config" | sed 's/^listen = "0\.0\.0\.0:/listen = "127.0.0.1:/' \
      | if [ -n "${ASSETS:-}" ]; then sed 's/^max_pending_feeds = .*/max_pending_feeds = 2048/'; else cat; fi
    tail -n +"$FEEDS_AT" node/all-feeds.toml
    for extra in ${EXTRA_FEEDS[@]+"${EXTRA_FEEDS[@]}"}; do
      printf '\n'
      cat "$extra"
    done
  } >"$config.new"
  mv "$config.new" "$config"
  echo "node$i  $(python3 -c 'import sys,json; print(json.load(open(sys.argv[1]))["address"])' "$node/node-entry.json")  ws://127.0.0.1:$port/v2/ws"
done

say "a client key, listed"
key_out=$(scripts/client-key.sh --out "$DIR/client.key")
ADDRESS=$(awk '/^address/ {print $2}' <<<"$key_out")
ENV=local scripts/add-client.sh --identity "$IDENTITY" --address "$ADDRESS" \
  --expires $(($(date +%s) + 30 * 86400)) >/dev/null 2>&1 || die "add_client failed"
echo "client  $ADDRESS  $DIR/client.key"

say "start"
for i in $(seq 1 "$NODES"); do
  start "node$i" "$DIR/node$i.log" "$BIN/oracle-node" start "$DIR/node$i/config.toml"
done
for i in $(seq 1 "$NODES"); do
  health="http://127.0.0.1:$((8800 + i))/v2/health"
  for _ in $(seq 1 120); do
    ! curl -sf "$health" >/dev/null || break
    sleep 0.5
  done
  curl -sf "$health" >/dev/null || die "node$i does not serve after 60 s; see $DIR/node$i.log"
done

# Written last and renamed, so a reader never sees half a file.
cat >"$DIR/stack.env.new" <<EOF
CANISTER="$CANISTER"
GATEWAY="$GATEWAY"
ROOT_KEY="$ROOT_KEY"
GOVERNANCE="$GOV"
NODES=$NODES
CLIENT_KEY="$DIR/client.key"
SYMBOLS="${SYMBOLS[*]}"
EOF
mv "$DIR/stack.env.new" "$DIR/stack.env"

cat <<EOF

The oracle runs on the local network:
  nodes      ws://127.0.0.1:8801/v2/ws to ws://127.0.0.1:880$NODES/v2/ws
  client     $DIR/client.key, listed
  stack      $DIR/stack.env
  logs       $DIR/*.log
For the web proxy, run scripts/dev.sh in the oracle-proxy repo.
Stop a node to watch the quorum react: kill <pid> (node pids: ${PIDS[*]}).
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
