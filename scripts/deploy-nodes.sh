#!/usr/bin/env bash
# Builds a commit of oracle-node and rolls it out to node hosts over SSH, one
# host at a time. Each host keeps its previous binary as `<binary>.prev`.
#
#   scripts/deploy-nodes.sh --health-url https://feeds.example.com/health node-a node-b node-c
#   scripts/deploy-nodes.sh --commit 38952c4 --yes node-a
#
# Each host is an SSH name that logs in as root with a key, and runs the
# `oracle-node` unit that `oracle-node init` installs. The commit must be on
# GitHub: release/install.sh at that commit compiles the node on one host of
# each architecture, at the lowest CPU priority, while the node keeps running.
# A host of the same architecture gets a copy when its glibc is new enough.
#
# Before each restart the script waits for the web proxy's full quorum
# (--health-url, its /health). After it, the script waits for a status line of
# the new process with every feed up, and it stops at the first host that fails.
# Works with the bash 3.2 that macOS ships.
set -euo pipefail

USAGE="usage: scripts/deploy-nodes.sh [--commit REF] [--health-url URL] [--yes] HOST..."
REPO=${ORACLE_REPO:-markoutlabs/oracle-node}
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
COMMIT=HEAD
HEALTH_URL=""
YES=""
HOSTS=()

say() { printf '%s\n' "$*"; }
die() {
  printf 'deploy-nodes: %s\n' "$*" >&2
  exit 1
}

while [ $# -gt 0 ]; do
  case $1 in
    -h | --help) say "$USAGE"; exit 0 ;;
    --commit) [ $# -ge 2 ] || die "$USAGE"; COMMIT=$2; shift 2 ;;
    --health-url) [ $# -ge 2 ] || die "$USAGE"; HEALTH_URL=$2; shift 2 ;;
    --yes) YES=1; shift ;;
    -*) die "unknown flag $1; $USAGE" ;;
    *) HOSTS+=("$1"); shift ;;
  esac
done
[ ${#HOSTS[@]} -gt 0 ] || die "$USAGE"

# `on` feeds the remote shell a script on stdin; `run` keeps stdin for the terminal.
on() {
  local host=$1
  shift
  ssh -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=30 "$host" "$@"
}
run() {
  local host=$1
  shift
  ssh -n -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=30 "$host" "$@"
}

# Prints the architecture, the glibc version, and the free kB under /root.
facts() {
  on "$1" bash -s <<'REMOTE'
set -eu
[ "$(id -u)" = 0 ] || { echo "the login is not root" >&2; exit 1; }
systemctl cat oracle-node >/dev/null 2>&1 || { echo "no oracle-node unit" >&2; exit 1; }
printf '%s %s %s\n' "$(uname -m)" "$(getconf GNU_LIBC_VERSION | cut -d ' ' -f 2)" \
  "$(df -Pk /root | awk 'NR == 2 { print $4 }')"
REMOTE
}

build() {
  on "$1" bash -s -- "$REPO" "$SHA" "$STAGE" <<'REMOTE'
set -eu
repo=$1 sha=$2 stage=$3
curl -fsSL "https://raw.githubusercontent.com/$repo/$sha/release/install.sh" -o "$stage.install.sh"
if ! nice -n 19 sh "$stage.install.sh" --version "$sha" --to "$stage" >"$stage.log" 2>&1; then
  tail -n 20 "$stage.log" >&2
  exit 1
fi
REMOTE
}

# The newest glibc that the staged binary needs, or nothing when objdump is missing.
needs_glibc() {
  run "$1" "objdump -T '$STAGE/oracle-node' 2>/dev/null | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -n 1 | cut -d _ -f 2" || true
}

# A glibc version as one number: 2.39 is 2039.
glibc_number() { echo $((${1%%.*} * 1000 + 10#${1#*.})); }

swap() {
  on "$1" bash -s -- "$STAGE" <<'REMOTE'
set -eu
stage=$1
bin=$(systemctl show -p ExecStart oracle-node | grep -o 'path=[^ ;]*' | head -n 1 | cut -d = -f 2)
[ -n "$bin" ] || { echo "cannot read the unit's binary" >&2; exit 1; }
cp -p "$bin" "$bin.prev"
install -m 0755 "$stage/oracle-node" "$bin"
systemctl restart oracle-node
systemctl is-active --quiet oracle-node
REMOTE
}

# Waits up to 3 minutes for a status line of the new process with every feed up.
node_ready() {
  on "$1" bash -s <<'REMOTE'
set -u
pid=$(systemctl show -p MainPID --value oracle-node)
for _ in $(seq 36); do
  line=$(journalctl -u oracle-node _PID="$pid" -o cat --no-pager | grep ' status ' | tail -n 1)
  feeds=$(grep -oE 'feeds=[0-9]+/[0-9]+' <<<"$line" | cut -d = -f 2)
  if [ -n "$feeds" ] && [ "${feeds%/*}" = "${feeds#*/}" ]; then
    echo "${line#*INFO }"
    grep 'open files' "/proc/$pid/limits" | tr -s ' '
    exit 0
  fi
  sleep 5
done
echo "no status line with every feed up after 3 minutes" >&2
exit 1
REMOTE
}

# Waits up to 3 minutes until the proxy is ok with every node connected.
quorum() {
  [ -n "$HEALTH_URL" ] || return 0
  local status connected nodes
  for _ in $(seq 36); do
    read -r status connected nodes <<<"$(curl -fsS --max-time 10 "$HEALTH_URL" 2>/dev/null |
      python3 -c 'import json, sys; d = json.load(sys.stdin); print(d["status"], d["connected"], d["nodes"])' \
        2>/dev/null || true)"
    if [ "${status:-}" = ok ] && [ -n "${nodes:-}" ] && [ "$connected" = "$nodes" ]; then
      say "  proxy: ok, $connected of $nodes nodes"
      return 0
    fi
    sleep 5
  done
  die "the proxy at $HEALTH_URL has not had its full quorum for 3 minutes"
}

git -C "$ROOT" fetch -q origin
SHA=$(git -C "$ROOT" rev-parse --verify -q "$COMMIT^{commit}") || die "no commit $COMMIT"
git -C "$ROOT" branch -r --contains "$SHA" | grep -q . ||
  die "push $SHA first: each build host fetches it from GitHub"
STAGE=/root/oracle-node-${SHA:0:12}
say "Commit $SHA, staged in $STAGE on each host."

say "1. Check the hosts"
ARCH=() GLIBC=() FREE=()
for i in "${!HOSTS[@]}"; do
  line=$(facts "${HOSTS[i]}") || die "${HOSTS[i]}: the check failed"
  read -r "ARCH[$i]" "GLIBC[$i]" "FREE[$i]" <<<"$line"
  say "  ${HOSTS[i]}: ${ARCH[i]}, glibc ${GLIBC[i]}, $((FREE[i] / 1048576)) GB free"
done

say "2. Build, one host of each architecture, in parallel (about 10 minutes)"
LOGS=$(mktemp -d)
BUILDERS=() PIDS=()
for i in "${!HOSTS[@]}"; do
  best=$i
  for j in "${!HOSTS[@]}"; do
    if [ "${ARCH[j]}" = "${ARCH[i]}" ] && [ "${FREE[j]}" -gt "${FREE[best]}" ]; then best=$j; fi
  done
  if [ "$best" = "$i" ]; then
    say "  ${HOSTS[i]}: building, the log is $STAGE.log there"
    build "${HOSTS[i]}" >"$LOGS/$i" 2>&1 &
    BUILDERS+=("$i") PIDS+=($!)
  fi
done
for k in "${!PIDS[@]}"; do
  wait "${PIDS[k]}" || { cat "$LOGS/${BUILDERS[k]}" >&2; die "${HOSTS[${BUILDERS[k]}]}: the build failed"; }
done

say "3. Stage on the other hosts"
for i in "${!HOSTS[@]}"; do
  from=""
  for b in "${BUILDERS[@]}"; do
    if [ "${ARCH[b]}" = "${ARCH[i]}" ]; then from=$b; fi
  done
  if [ "$from" != "$i" ]; then
    need=$(needs_glibc "${HOSTS[from]}")
    if [ -n "$need" ] && [ "$(glibc_number "$need")" -le "$(glibc_number "${GLIBC[i]}")" ]; then
      say "  ${HOSTS[i]}: copy from ${HOSTS[from]} (needs glibc $need, has ${GLIBC[i]})"
      run "${HOSTS[i]}" "mkdir -p '$STAGE'"
      scp -3 -q -o BatchMode=yes "${HOSTS[from]}:$STAGE/oracle-node" "${HOSTS[i]}:$STAGE/oracle-node"
    else
      say "  ${HOSTS[i]}: building, its glibc ${GLIBC[i]} is older than the binary needs"
      build "${HOSTS[i]}" || die "${HOSTS[i]}: the build failed"
    fi
  fi
  say "  ${HOSTS[i]}: $(run "${HOSTS[i]}" "'$STAGE/oracle-node' --version")"
done

if [ -z "$YES" ]; then
  answer=""
  read -r -p "Restart ${#HOSTS[@]} nodes one at a time? Each restart pauses prices until the node is back. [y/N] " answer
  [ "$answer" = y ] || die "nothing restarted; the binaries stay staged in $STAGE"
fi

say "4. Restart one host at a time"
quorum
for host in "${HOSTS[@]}"; do
  say "  $host: swap and restart"
  swap "$host" || die "$host: the restart failed; roll back with: ssh $host 'install -m 0755 /usr/local/bin/oracle-node.prev /usr/local/bin/oracle-node && systemctl restart oracle-node'"
  node_ready "$host" | sed 's/^/    /' || die "$host: not healthy; roll back with: ssh $host 'install -m 0755 /usr/local/bin/oracle-node.prev /usr/local/bin/oracle-node && systemctl restart oracle-node'"
  quorum
done
say "Done: ${#HOSTS[@]} nodes run $SHA."
