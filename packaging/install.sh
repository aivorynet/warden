#!/bin/sh
# Install Aivory Warden on macOS or Linux without a package manager.
#
#   curl -fsSL https://github.com/aivorynet/warden/releases/latest/download/install.sh | sh
#   curl -fsSL .../install.sh | sh -s -- --service --extension
#
# It downloads the release archive for this OS and CPU, checks its SHA-256 against SHA256SUMS,
# and installs `aivory-warden` and `awd` into $WARDEN_PREFIX/bin (default ~/.local/bin).
#
# Flags (off by default):
#   --service     run `aivory-warden service install` (start the daemon at login)
#   --extension   run `aivory-warden extension install` (register the Edge/Chrome native host)
# Environment:
#   WARDEN_VERSION  fixed version, for example 2026.11.0 (default: latest release)
#   WARDEN_PREFIX   install prefix (default: $HOME/.local)
set -eu

repo="aivorynet/warden"
prefix="${WARDEN_PREFIX:-$HOME/.local}"
bin="$prefix/bin"
do_service=0
do_extension=0

for arg in "$@"; do
  case "$arg" in
    --service) do_service=1 ;;
    --extension) do_extension=1 ;;
    -h | --help) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "warden: unknown option $arg" >&2; exit 1 ;;
  esac
done

case "$(uname -s)" in
  Darwin) os=apple-darwin ;;
  Linux) os=unknown-linux-gnu ;;
  *) echo "warden: this script supports macOS and Linux. On Windows use install.ps1 or: winget install Aivory.Warden" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  arm64 | aarch64) arch=aarch64 ;;
  x86_64 | amd64) arch=x86_64 ;;
  *) echo "warden: no build for CPU $(uname -m)" >&2; exit 1 ;;
esac

target="$arch-$os"
name="aivory-warden-$target"
if [ -n "${WARDEN_VERSION:-}" ]; then
  base="https://github.com/$repo/releases/download/v${WARDEN_VERSION#v}"
else
  base="https://github.com/$repo/releases/latest/download"
fi

fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$2" "$1"
  else
    echo "warden: curl or wget is required" >&2
    exit 1
  fi
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d' ' -f1
  else
    echo "warden: sha256sum or shasum is required" >&2
    exit 1
  fi
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

echo "warden: downloading $base/$name.tar.gz"
fetch "$base/$name.tar.gz" "$tmp/$name.tar.gz"
fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS"

expected="$(awk -v f="$name.tar.gz" '{ n=$2; sub(/^\*/, "", n); if (n == f) print $1 }' "$tmp/SHA256SUMS")"
if [ -z "$expected" ]; then
  echo "warden: $name.tar.gz is not listed in SHA256SUMS" >&2
  exit 1
fi
actual="$(sha256_of "$tmp/$name.tar.gz")"
if [ "$expected" != "$actual" ]; then
  echo "warden: SHA-256 mismatch for $name.tar.gz (expected $expected, got $actual)" >&2
  exit 1
fi
echo "warden: SHA-256 ok"

tar -xzf "$tmp/$name.tar.gz" -C "$tmp"
mkdir -p "$bin"
for f in aivory-warden awd; do
  cp "$tmp/$name/$f" "$bin/$f.new"
  chmod +x "$bin/$f.new"
  mv -f "$bin/$f.new" "$bin/$f"
done
if [ "$(uname -s)" = Darwin ]; then
  xattr -d com.apple.quarantine "$bin/aivory-warden" "$bin/awd" 2>/dev/null || true
fi
echo "warden: installed aivory-warden and awd in $bin"

if [ "$do_service" = 1 ]; then
  "$bin/aivory-warden" service install
fi
if [ "$do_extension" = 1 ]; then
  "$bin/aivory-warden" extension install
fi

case ":$PATH:" in
  *":$bin:"*) ;;
  *) echo "warden: add $bin to your PATH" ;;
esac
echo "warden: next step: awd init"
