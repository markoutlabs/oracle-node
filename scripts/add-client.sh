#!/usr/bin/env bash
# Authorises a client in the registry canister until a date. Run it as
# governance: the identity that controls the canister.
#
#   scripts/add-client.sh --identity tapray --address 0x… --expires 2027-01-01
#   ENV=local scripts/add-client.sh --identity oracle-e2e --address 0x… --expires 1798761600
#
# `--expires` takes an ISO 8601 date or time, UTC unless it names an offset, or
# unix seconds. A client address is listed once, ever: a removed client never
# comes back.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

flags "identity address expires" \
  "usage: scripts/add-client.sh --identity NAME --address 0x… --expires DATE" "$@"
[[ $ADDRESS =~ ^0x[0-9a-fA-F]{40}$ ]] || die "--address must be 0x and 40 hex digits"

EXPIRES_AT=$(python3 - "$EXPIRES" <<'EOF'
import datetime, sys
text = sys.argv[1]
try:
    if text.isdigit():
        at = datetime.datetime.fromtimestamp(int(text), datetime.timezone.utc)
    else:
        at = datetime.datetime.fromisoformat(text)
        if at.tzinfo is None:
            at = at.replace(tzinfo=datetime.timezone.utc)
except (ValueError, OverflowError) as error:
    sys.exit(f"add-client: --expires {text}: {error}")
print(f"expires  {at.astimezone(datetime.timezone.utc):%Y-%m-%d %H:%M:%S} UTC", file=sys.stderr)
print(int(at.timestamp()))
EOF
) || exit 1
echo "client   $ADDRESS" >&2

governance_call "$IDENTITY" add_client "(\"$ADDRESS\", $EXPIRES_AT : nat64)" "Authorise this client"
