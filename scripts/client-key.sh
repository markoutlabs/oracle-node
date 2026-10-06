#!/usr/bin/env bash
# Makes a client API key on this machine (SPEC §6.1) and prints the command
# that registers it. The key stays with the client; governance needs only its
# address.
#
#   scripts/client-key.sh --out ~/oracle-client/client.key
#
# The key is plaintext hex in a 0600 file, which the SDK reads with
# `Signer::from_hex`. An existing file is never overwritten.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

flags "out" "usage: scripts/client-key.sh --out FILE" "$@"
[ ! -e "$OUT" ] || die "$OUT exists; a key is never overwritten"
mkdir -p "$(dirname "$OUT")"

output=$(cargo run -q --locked --manifest-path "$ROOT/Cargo.toml" \
  -p oracle-client --example client_key -- --out "$OUT")
address=$(awk '/^address/ {print $2}' <<<"$output")
[ -n "$address" ] || die "client_key printed no address: $output"

echo "address  $address"
echo "key      $OUT  (keep it on the client's machine)"
echo
echo "Governance registers it with:"
echo "  scripts/add-client.sh --identity <controller> --address $address --expires <YYYY-MM-DD>"
