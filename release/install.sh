#!/bin/sh
# Builds oracle-node from source and installs it. When the build needs a tool
# that is missing, it installs it: a C compiler through the system's package
# manager, and Rust through rustup. The web proxy has its own repo.
#
#   curl -fsSL https://raw.githubusercontent.com/markoutlabs/oracle-node/main/release/install.sh | sh
#   sudo oracle-node init
#
#   curl -fsSL …/install.sh | sh -s -- --version v0.1.0 --to "$HOME/bin"
#
# Environment: ORACLE_VERSION, ORACLE_INSTALL_DIR and ORACLE_REPO set the same
# things as --version, --to and the source repository.
set -eu

REPO="${ORACLE_REPO:-markoutlabs/oracle-node}"
VERSION="${ORACLE_VERSION:-main}"
INSTALL_DIR="${ORACLE_INSTALL_DIR:-}"
# The workspace's rust-version.
MIN_RUST=1.85
# Below this much memory (kB), the build runs one job at a time.
LOW_MEMORY_KB=3500000
STEPS=4
STEP=0

say() { printf '%s\n' "$*"; }
fail() {
  printf '\ninstall.sh: %s\n' "$*" >&2
  exit 1
}

usage() {
  say "usage: install.sh [node] [--version <tag, branch or commit>] [--to <dir>]"
  say ""
  say "  node      install oracle-node (the default, and the only component)"
  say "  --version what to build: a tag such as v0.1.0, a branch, or a commit"
  say "            (default: main)"
  say "  --to      the directory for the binary (default: /usr/local/bin, or"
  say "            ~/.local/bin without root or sudo)"
}

# Seconds since $1, as "42s" or "3m 07s".
elapsed() {
  seconds=$(($(date +%s) - $1))
  if [ "$seconds" -ge 60 ]; then
    printf '%dm %02ds' $((seconds / 60)) $((seconds % 60))
  else
    printf '%ds' "$seconds"
  fi
}

# Starts a numbered step.
step() {
  STEP=$((STEP + 1))
  step_started="$(date +%s)"
  printf '\n[%s/%s] %s\n' "$STEP" "$STEPS" "$*"
}

step_done() {
  say "      done in $(elapsed "$step_started")"
}

# Shows a command, then runs it with its output on the terminal.
run() {
  say "  + $*"
  "$@"
}

# Runs a command as root: directly, or through sudo.
as_root() {
  if [ "$(id -u)" -eq 0 ]; then
    run "$@"
  elif command -v sudo >/dev/null 2>&1; then
    run sudo "$@"
  else
    fail "needs root or sudo to run: $*"
  fi
}

# Downloads $1 to $2, over HTTPS only.
fetch() {
  if command -v curl >/dev/null 2>&1; then
    run curl --proto '=https' --tlsv1.2 -fsSL -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then
    run wget --https-only -q -O "$2" "$1"
  else
    fail "needs curl or wget"
  fi
}

# Exit 0 if version $1 is at least version $2 (dotted numbers).
at_least() {
  [ "$(printf '%s\n%s\n' "$2" "$1" | sort -t . -k 1,1n -k 2,2n | head -n 1)" = "$2" ]
}

memory_kb() {
  if [ -r /proc/meminfo ]; then
    awk '/^MemTotal:/ { print $2 }' /proc/meminfo
  fi
}

# What runs where, before anything changes.
describe() {
  os="$(uname -s) $(uname -m)"
  if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091 # Linux distributions have it.
    os="$os, $(. /etc/os-release && printf '%s' "${PRETTY_NAME:-$ID}")"
  fi
  cpus="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo '?')"
  memory="$(memory_kb)"
  free="$(df -Pk "${TMPDIR:-/tmp}" | awk 'NR == 2 { printf "%.1f GB", $4 / 1048576 }')"
  say "oracle-node installer"
  say "  source   https://github.com/$REPO at $VERSION"
  say "  binary   $INSTALL_DIR/oracle-node"
  say "  system   $os"
  if [ -n "$memory" ]; then
    memory="$(awk -v kb="$memory" 'BEGIN { printf "%.1f GB", kb / 1048576 }')"
    say "           $cpus CPUs, $memory memory, $free free in ${TMPDIR:-/tmp}"
  else
    say "           $cpus CPUs, $free free in ${TMPDIR:-/tmp}"
  fi
}

# ring and secp256k1 compile C code, so the build needs a C compiler.
ensure_compiler() {
  step "C compiler"
  for compiler in cc gcc; do
    if command -v "$compiler" >/dev/null 2>&1; then
      say "  found: $("$compiler" --version 2>&1 | head -n 1)"
      step_done
      return
    fi
  done
  say "  none found; installing one with the package manager"
  if [ "$(uname -s)" = Darwin ]; then
    fail "install the Xcode command line tools first: xcode-select --install"
  elif command -v apt-get >/dev/null 2>&1; then
    as_root apt-get update -q
    as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends build-essential
  elif command -v dnf >/dev/null 2>&1; then
    as_root dnf install -y gcc
  elif command -v yum >/dev/null 2>&1; then
    as_root yum install -y gcc
  elif command -v apk >/dev/null 2>&1; then
    as_root apk add --no-cache build-base
  elif command -v zypper >/dev/null 2>&1; then
    as_root zypper -n install gcc
  elif command -v pacman >/dev/null 2>&1; then
    as_root pacman -S --noconfirm --needed gcc
  else
    fail "no C compiler, and no known package manager to install one"
  fi
  step_done
}

# Sets CARGO to a cargo whose Rust is at least MIN_RUST, and installs Rust
# through rustup when there is none.
ensure_rust() {
  step "Rust $MIN_RUST or newer"
  if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck disable=SC1091 # rustup writes it.
    . "$HOME/.cargo/env"
  fi
  if command -v rustup >/dev/null 2>&1; then
    say "  found rustup; checking the stable toolchain"
    run rustup toolchain install stable --profile minimal
    CARGO="rustup run stable cargo"
    say "  using: $(rustup run stable rustc --version)"
    step_done
    return
  fi
  if command -v cargo >/dev/null 2>&1 && command -v rustc >/dev/null 2>&1; then
    have="$(rustc --version | cut -d ' ' -f 2)"
    if at_least "$have" "$MIN_RUST"; then
      CARGO=cargo
      say "  found: $(rustc --version)"
      step_done
      return
    fi
    say "  found Rust $have, older than $MIN_RUST; installing a newer one with rustup"
  else
    say "  none found; installing Rust with rustup"
  fi
  fetch https://sh.rustup.rs "$tmp/rustup-init.sh"
  # Leaves the shell profile alone, and installs beside a system Rust if any.
  run env RUSTUP_INIT_SKIP_PATH_CHECK=yes sh "$tmp/rustup-init.sh" -y \
    --profile minimal --default-toolchain stable --no-modify-path
  CARGO="$HOME/.cargo/bin/cargo"
  say "  installed Rust in $HOME/.cargo. Your shell profile is unchanged."
  step_done
}

build() {
  step "Build oracle-node"
  say "  This takes about 5 to 10 minutes. Cargo shows its progress below."
  memory="$(memory_kb)"
  if [ -n "$memory" ] && [ "$memory" -lt "$LOW_MEMORY_KB" ]; then
    say "  Less than 3.5 GB of memory: one job at a time, which is slower."
    export CARGO_BUILD_JOBS=1
  fi
  # On the PATH only so that cargo does not warn about a PATH without it.
  (
    # shellcheck disable=SC2030 # Only the build sees it.
    PATH="$tmp/root/bin:$PATH"
    # shellcheck disable=SC2086 # CARGO can be a command with arguments.
    run $CARGO install --locked --git "https://github.com/$REPO" \
      "$(source_flag)" "$VERSION" --root "$tmp/root" oracle-node
  )
  step_done
}

install_binary() {
  step "Install to $INSTALL_DIR"
  # shellcheck disable=SC2086 # SUDO is empty or one word.
  run $SUDO mkdir -p "$INSTALL_DIR"
  # shellcheck disable=SC2086
  run $SUDO install -m 0755 "$tmp/root/bin/oracle-node" "$INSTALL_DIR/oracle-node"
  say "  installed: $("$INSTALL_DIR/oracle-node" --version)"
  step_done
}

choose_dir() {
  SUDO=""
  if [ -n "$INSTALL_DIR" ]; then
    return
  fi
  # Not under a home folder: the service user cannot open one.
  INSTALL_DIR=/usr/local/bin
  if [ "$(id -u)" -eq 0 ] || [ -w "$INSTALL_DIR" ]; then
    return
  fi
  if command -v sudo >/dev/null 2>&1; then
    SUDO=sudo
    return
  fi
  INSTALL_DIR="$HOME/.local/bin"
}

# The cargo flag that selects $VERSION: a tag, a commit or a branch.
source_flag() {
  case "$VERSION" in
    v[0-9]*) printf '%s' "--tag" ;;
    *)
      if printf '%s' "$VERSION" | grep -Eq '^[0-9a-f]{7,40}$'; then
        printf '%s' "--rev"
      else
        printf '%s' "--branch"
      fi
      ;;
  esac
}

main() {
  while [ $# -gt 0 ]; do
    case "$1" in
      node) ;;
      proxy) fail "oracle-proxy has its own repo and installer" ;;
      --version)
        [ $# -ge 2 ] || fail "--version needs a tag, a branch or a commit"
        VERSION="$2"
        shift
        ;;
      --to)
        [ $# -ge 2 ] || fail "--to needs a directory"
        INSTALL_DIR="$2"
        shift
        ;;
      -h | --help)
        usage
        exit 0
        ;;
      *)
        usage >&2
        exit 2
        ;;
    esac
    shift
  done

  case "$(uname -s)" in
    Linux | Darwin) ;;
    *) fail "builds on Linux and macOS only, not $(uname -s)" ;;
  esac
  started="$(date +%s)"
  choose_dir
  describe
  if [ -n "$SUDO" ]; then
    say "  Installing to $INSTALL_DIR needs sudo. It can ask for your password."
  fi

  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  trap 'exit 130' INT TERM

  ensure_compiler
  ensure_rust
  build
  install_binary

  say ""
  say "Done in $(elapsed "$started")."
  # shellcheck disable=SC2031 # The caller's PATH, without the build's change.
  case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *) say "Add $INSTALL_DIR to your PATH to run oracle-node by name." ;;
  esac
  say ""
  say "Next: run 'sudo oracle-node init'. It sets up the node as a service and starts it."
}

# Everything runs from here, so a download cut short runs nothing.
main "$@"
