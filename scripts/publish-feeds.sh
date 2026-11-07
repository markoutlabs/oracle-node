#!/usr/bin/env bash
# Publishes the network's feed set: the [[feeds]] of node/all-feeds.toml and
# node/assets.toml, after every check that a node runs on them. Run it as
# governance: the identity that controls the canister. Each node takes the new
# set while it runs, in its own slot (SPEC §3.8).
#
#   PUSH=60,2,60 scripts/publish-feeds.sh --identity tapray
#   ENV=local PUSH=2,10,1 scripts/publish-feeds.sh --identity oracle-e2e
#
# PUSH sets every node's push pace: heartbeat seconds, deviation in basis
# points, and minimum interval seconds. It is required: without it, each node
# pushes at its own pace, and the canister pays for each push. The production
# pace is PUSH=60,2,60 with a 180 s price window (SPEC §3.7).
# The script shows which feeds the publish adds, removes and changes, against
# the set the canister serves now.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

flags "identity" "usage: PUSH=H,D,I scripts/publish-feeds.sh --identity NAME" "$@"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

[ -n "${PUSH:-}" ] || die "PUSH is required: heartbeat,deviation,interval, such as PUSH=60,2,60 (SPEC §3.7)"
IFS=, read -r heartbeat deviation interval <<<"$PUSH"
[ -n "${interval:-}" ] || die "PUSH takes three numbers: heartbeat,deviation,interval"
PACE=(--push-heartbeat-secs "$heartbeat" --push-deviation-bps "$deviation"
  --push-min-interval-secs "$interval")
# A first build takes minutes, so cargo shows its progress.
echo "building oracle-node for the export" >&2
(cd "$ROOT" && cargo build --release -p oracle-node --bin oracle-node)
(cd "$ROOT" && target/release/oracle-node export-feeds \
  node/all-feeds.toml node/assets.toml --candid "$WORK/args.bin" "${PACE[@]}") >"$WORK/content.json"

# The published set, as the nodes read it, for the diff only: the canister signs
# what this sends. Before the first publish there is none.
ID=$(cd "$ROOT" && icp canister status oracle_registry -e "$ENV" --id-only)
if [ "$ENV" = ic ]; then
  URL="https://$ID.raw.icp0.io/feeds.json"
else
  GATEWAY=$(cd "$ROOT" && icp network status --json \
    | python3 -c 'import sys,json; print(json.load(sys.stdin)["gateway_url"].rstrip("/"))')
  URL="$GATEWAY/feeds.json?canisterId=$ID"
fi
curl -sf --max-time 30 "$URL" >"$WORK/current.json" || echo '{}' >"$WORK/current.json"

SUMMARY=$(python3 - "$WORK/content.json" "$WORK/current.json" <<'PY'
import json, sys
new = json.load(open(sys.argv[1]))
old_feeds = {feed["symbol"]: feed for feed in json.load(open(sys.argv[2])).get("feeds", [])}
new_feeds = {feed["symbol"]: feed for feed in new["feeds"]}
added = sorted(set(new_feeds) - set(old_feeds))
removed = sorted(set(old_feeds) - set(new_feeds))
changed = sorted(s for s in new_feeds if s in old_feeds and new_feeds[s] != old_feeds[s])
for label, symbols in (("adds", added), ("removes", removed), ("changes", changed)):
    shown = ", ".join(symbols[:12]) + (f", and {len(symbols) - 12} more" if len(symbols) > 12 else "")
    print(f"{label:8} {len(symbols):4}  {shown}", file=sys.stderr)
print(f"push     {new.get('push')}", file=sys.stderr)
print(f"{len(new_feeds)} feeds: +{len(added)} -{len(removed)} ~{len(changed)}")
PY
)

governance_call "$IDENTITY" set_feed_set "@$WORK/args.bin" "Publish the feed set ($SUMMARY)"
