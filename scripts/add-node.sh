#!/usr/bin/env bash
# Lists a node in the registry canister from the entry `oracle-node init`
# wrote. Run it as governance: the identity that controls the canister.
#
#   scripts/add-node.sh --identity tapray --json oracle-node/node-entry.json
#   scripts/add-node.sh --identity tapray --json '{"address": "0x…", "endpoints": ["wss://…"], "weight": 1}'
#   ENV=local scripts/add-node.sh --identity oracle-e2e --json target/smoke/node/node-entry.json
#
# `--json` takes the entry itself or a file that holds it. An address is listed
# once, ever, and its endpoints cannot change later.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

flags "identity json" "usage: scripts/add-node.sh --identity NAME --json ENTRY_OR_FILE" "$@"

# Prints the entry for a person on stderr, and the Candid argument on stdout.
# Candid escapes `"` and `\` as JSON does, so a JSON string of the compact
# entry is that argument.
ARG=$(python3 - "$JSON" <<'EOF'
import json, sys
source = sys.argv[1]
try:
    entry = json.loads(source if source.lstrip().startswith("{") else open(source).read())
except (OSError, ValueError) as error:
    sys.exit(f"add-node: {source}: {error}")
print(json.dumps(entry, indent=2, ensure_ascii=False), file=sys.stderr)
compact = json.dumps(entry, separators=(",", ":"), ensure_ascii=False)
print("(" + json.dumps(compact, ensure_ascii=False) + ")")
EOF
) || exit 1

governance_call "$IDENTITY" add_node "$ARG" "List this node"
