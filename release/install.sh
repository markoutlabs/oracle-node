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

say() { printf '%s\n' "$*"; }
fail() {
  printf 'install.sh: %s\n' "$*" >&2
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

# Downloads $1 to $2, over HTTPS only.
fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -fsSL -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget --https-only -q -O "$2" "$1"
  else
    fail "needs curl or wget"
  fi
}

# Exit 0 if version $1 is at least version $2 (dotted numbers).
at_least() {
  [ "$(printf '%s\n%s\n' "$2" "$1" | sort -t . -k 1,1n -k 2,2n | head -n 1)" = "$2" ]
}

# Runs a step with its output in a log file. On a failure, shows the end of
# the log: package managers and build scripts print much more than a user needs.
quietly() {
  log="$tmp/$1.log"
  kept="${TMPDIR:-/tmp}/oracle-node-install-$1.log"
  shift
  if ! "$@" >"$log" 2>&1; then
    tail -n 40 "$log" >&2
    # The temporary folder goes at exit; the log of a failure stays.
    cp "$log" "$kept" 2>/dev/null || kept="(not kept)"
    fail "failed: $* (full log: $kept)"
  fi
}

# Runs a command as root: directly, or through sudo.
as_root() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    fail "needs root or sudo to run: $*"
  fi
}

# ring and secp256k1 compile C code, so the build needs a C compiler.
ensure_compiler() {
  if command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1; then
    return
  fi
  say "Installing a C compiler"
  if [ "$(uname -s)" = Darwin ]; then
    fail "install the Xcode command line tools first: xcode-select --install"
  elif command -v apt-get >/dev/null 2>&1; then
    quietly packages as_root apt-get update -qq
    quietly packages as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq build-essential
  elif command -v dnf >/dev/null 2>&1; then
    quietly packages as_root dnf install -y -q gcc
  elif command -v yum >/dev/null 2>&1; then
    quietly packages as_root yum install -y -q gcc
  elif command -v apk >/dev/null 2>&1; then
    quietly packages as_root apk add --no-cache build-base
  elif command -v zypper >/dev/null 2>&1; then
    quietly packages as_root zypper -n -q install gcc
  elif command -v pacman >/dev/null 2>&1; then
    quietly packages as_root pacman -S --noconfirm --needed gcc
  else
    fail "no C compiler, and no known package manager to install one"
  fi
}

# Sets CARGO to a cargo whose Rust is at least MIN_RUST, and installs Rust
# through rustup when there is none.
ensure_rust() {
  if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck disable=SC1091 # rustup writes it.
    . "$HOME/.cargo/env"
  fi
  if command -v rustup >/dev/null 2>&1; then
    quietly rustup rustup toolchain install stable --profile minimal
    CARGO="rustup run stable cargo"
    return
  fi
  if command -v cargo >/dev/null 2>&1 && command -v rustc >/dev/null 2>&1; then
    have="$(rustc --version | cut -d ' ' -f 2)"
    if at_least "$have" "$MIN_RUST"; then
      CARGO=cargo
      return
    fi
    say "Rust $have is older than $MIN_RUST; installing a newer one with rustup"
  else
    say "Installing Rust with rustup"
  fi
  fetch https://sh.rustup.rs "$tmp/rustup-init.sh"
  # Leaves the shell profile alone, and installs beside a system Rust if any.
  quietly rustup env RUSTUP_INIT_SKIP_PATH_CHECK=yes sh "$tmp/rustup-init.sh" -y \
    --profile minimal --default-toolchain stable --no-modify-path
  CARGO="$HOME/.cargo/bin/cargo"
  say "Installed Rust in $HOME/.cargo. Your shell profile is unchanged."
}

choose_dir() {
  SUDO=""
  if [ -n "$INSTALL_DIR" ]; then
    return
  fi
  # Not under a home folder: the systemd unit cannot read one.
  INSTALL_DIR=/usr/local/bin
  if [ "$(id -u)" -eq 0 ] || [ -w "$INSTALL_DIR" ]; then
    return
  fi
  if command -v sudo >/dev/null 2>&1; then
    SUDO=sudo
    say "Installing to $INSTALL_DIR needs sudo."
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
  bin=oracle-node

  case "$(uname -s)" in
    Linux | Darwin) ;;
    *) fail "builds on Linux and macOS only, not $(uname -s)" ;;
  esac
  choose_dir

  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  trap 'exit 130' INT TERM

  ensure_compiler
  ensure_rust

  if [ -r /proc/meminfo ]; then
    memory="$(awk '/^MemTotal:/ { print $2 }' /proc/meminfo)"
    if [ "$memory" -lt "$LOW_MEMORY_KB" ]; then
      say "Less than 3.5 GB of memory: building one job at a time, which is slower."
      export CARGO_BUILD_JOBS=1
    fi
  fi

  say "Building $bin from $REPO at $VERSION. This takes about 5 to 10 minutes."
  # shellcheck disable=SC2086 # CARGO can be a command with arguments.
  quietly build $CARGO install --locked --git "https://github.com/$REPO" \
    "$(source_flag)" "$VERSION" --root "$tmp/root" "$bin"

  $SUDO mkdir -p "$INSTALL_DIR"
  $SUDO install -m 0755 "$tmp/root/bin/$bin" "$INSTALL_DIR/$bin"
  say "Installed $("$INSTALL_DIR/$bin" --version) to $INSTALL_DIR/$bin"

  case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *) say "Add $INSTALL_DIR to your PATH to run $bin by name." ;;
  esac

  say ""
  say "Next: run 'sudo oracle-node init'. It sets up the node as a service and starts it."
}

# Everything runs from here, so a download cut short runs nothing.
main "$@"
