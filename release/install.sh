#!/bin/sh
# Installs oracle-node from a GitHub release, after it checks the binary against
# the release's SHA256SUMS. The web proxy has its own repo and installer:
# https://github.com/pxr64/oracle-proxy
#
#   curl -fsSL https://github.com/pxr64/reimagined-octo-train/releases/latest/download/install.sh | sh
#   curl -fsSL …/install.sh | sh -s -- --version v0.1.0 --to "$HOME/bin"
#
# Environment: ORACLE_VERSION, ORACLE_INSTALL_DIR and ORACLE_REPO set the same
# things as --version, --to and the source repository.
set -eu

REPO="${ORACLE_REPO:-pxr64/reimagined-octo-train}"
VERSION="${ORACLE_VERSION:-latest}"
INSTALL_DIR="${ORACLE_INSTALL_DIR:-}"
# The release binaries link against this glibc or a newer one.
MIN_GLIBC=2.28

say() { printf '%s\n' "$*"; }
fail() {
  printf 'install.sh: %s\n' "$*" >&2
  exit 1
}

usage() {
  say "usage: install.sh [node] [--version <tag>] [--to <dir>]"
  say ""
  say "  node      install oracle-node (the default, and the only component)"
  say "  --version a release tag such as v0.1.0 (default: the latest release)"
  say "  --to      the directory for the binary (default: /usr/local/bin, or"
  say "            ~/.local/bin without root or sudo)"
}

# Download $1 to $2, over HTTPS only.
fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -fsSL -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget --https-only -q -O "$2" "$1"
  else
    fail "needs curl or wget"
  fi
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d ' ' -f 1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d ' ' -f 1
  else
    fail "needs sha256sum or shasum to check the download"
  fi
}

# Exit 0 if version $1 is at least version $2 (dotted numbers).
at_least() {
  [ "$(printf '%s\n%s\n' "$2" "$1" | sort -t . -k 1,1n -k 2,2n | head -n 1)" = "$2" ]
}

check_platform() {
  os="$(uname -s)"
  [ "$os" = Linux ] || fail "the release has Linux binaries only, not $os. Build from source: https://github.com/$REPO"
  case "$(uname -m)" in
    x86_64 | amd64) ARCH=amd64 ;;
    aarch64 | arm64) ARCH=arm64 ;;
    *) fail "no release binary for $(uname -m). Build from source: https://github.com/$REPO" ;;
  esac
  # musl systems such as Alpine cannot load a glibc binary.
  glibc="$(getconf GNU_LIBC_VERSION 2>/dev/null | cut -d ' ' -f 2 || true)"
  [ -n "$glibc" ] || fail "the binaries need glibc $MIN_GLIBC or newer, and this system has no glibc"
  at_least "$glibc" "$MIN_GLIBC" || fail "the binaries need glibc $MIN_GLIBC or newer; this system has $glibc"
}

choose_dir() {
  SUDO=""
  if [ -n "$INSTALL_DIR" ]; then
    return
  fi
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

main() {
  while [ $# -gt 0 ]; do
    case "$1" in
      node) ;;
      proxy) fail "oracle-proxy has its own installer: https://github.com/pxr64/oracle-proxy" ;;
      --version)
        [ $# -ge 2 ] || fail "--version needs a tag"
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

  check_platform
  choose_dir

  if [ "$VERSION" = latest ]; then
    base="https://github.com/$REPO/releases/latest/download"
  else
    base="https://github.com/$REPO/releases/download/$VERSION"
  fi
  asset="$bin-linux-$ARCH"

  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  trap 'exit 130' INT TERM

  say "Downloading $asset ($VERSION release of $REPO)"
  fetch "$base/$asset" "$tmp/$asset" || fail "cannot download $base/$asset"
  fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" || fail "cannot download $base/SHA256SUMS"

  expected="$(awk -v name="$asset" '$2 == name { print $1 }' "$tmp/SHA256SUMS")"
  [ -n "$expected" ] || fail "SHA256SUMS has no entry for $asset"
  actual="$(sha256 "$tmp/$asset")"
  [ "$actual" = "$expected" ] || fail "checksum mismatch for $asset: expected $expected, got $actual"
  say "Checksum OK: $actual"

  $SUDO mkdir -p "$INSTALL_DIR"
  $SUDO install -m 0755 "$tmp/$asset" "$INSTALL_DIR/$bin"
  say "Installed $("$INSTALL_DIR/$bin" --version) to $INSTALL_DIR/$bin"

  case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *) say "Add $INSTALL_DIR to your PATH to run $bin by name." ;;
  esac

  say ""
  say "Next: run 'oracle-node init' to create the node key and its config."
}

# Everything runs from here, so a download cut short runs nothing.
main "$@"
