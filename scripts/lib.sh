# Sourced by the scripts that call the registry canister as governance, the
# identity that controls it. Mainnet unless ENV names another environment.
# Works with the bash 3.2 that macOS ships.

ENV=${ENV:-ic}
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

die() {
  printf '%s: %s\n' "$(basename "$0" .sh)" "$*" >&2
  exit 1
}

upper() { tr 'a-z-' 'A-Z_' <<<"$1"; }

# Reads `--name value` or `--name=value` into NAME for each name in $1, and
# fails unless every one is set. $2 is the usage line.
flags() {
  local names=$1 usage=$2 name value var
  shift 2
  for name in $names; do printf -v "$(upper "$name")" '%s' ''; done
  while [ $# -gt 0 ]; do
    case $1 in
      -h | --help) echo "$usage"; exit 0 ;;
      --*=*) name=${1%%=*} value=${1#*=}; shift ;;
      --*) [ $# -ge 2 ] || die "$1 needs a value; $usage"; name=$1 value=$2; shift 2 ;;
      *) die "unknown argument $1; $usage" ;;
    esac
    name=${name#--}
    case " $names " in *" $name "*) ;; *) die "unknown flag --$name; $usage" ;; esac
    printf -v "$(upper "$name")" '%s' "$value"
  done
  for name in $names; do
    var=$(upper "$name")
    [ -n "${!var}" ] || die "$usage"
  done
}

# Runs a governance update call and fails unless the canister answers Ok.
# Mainnet asks first: each call publishes, and an address is used once, ever.
governance_call() { # identity, method, Candid arguments, what the call does
  local reply answer
  [ "$1" != anonymous ] || die "the anonymous identity is not governance"
  if [ "$ENV" = ic ]; then
    read -r -p "$4 on mainnet as $1? [y/N] " answer
    [ "$answer" = y ] || die "nothing was sent"
  fi
  reply=$(cd "$ROOT" && icp canister call oracle_registry "$2" "$3" -e "$ENV" --identity "$1" | tee /dev/stderr)
  grep -q "Ok = " <<<"$reply" || die "the canister refused $2"
}
