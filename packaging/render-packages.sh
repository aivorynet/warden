#!/usr/bin/env bash
# Render the winget manifests, the Scoop manifest and the Homebrew formula with the hashes of
# the release files. Usage: packaging/render-packages.sh <version> <dist-dir> <out-dir>
# <dist-dir> holds SHA256SUMS. The hashes come from that file.
set -euo pipefail

version="${1:?version, for example 2026.11.0}"
dist="${2:?folder with the release files}"
out="${3:?output folder}"
root="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$out"
out="$(cd "$out" && pwd)"

hash() {
  local h=""
  if [ -f "$dist/SHA256SUMS" ]; then
    h="$(awk -v f="$1" '{ n=$2; sub(/^\*/, "", n); if (n == f) print $1 }' "$dist/SHA256SUMS")"
  fi
  if [ -z "$h" ]; then
    echo "render-packages: no hash for $1" >&2
    h="MISSING"
  fi
  echo "$h"
}

win_x64=$(hash aivory-warden-x86_64-pc-windows-msvc.zip)
win_arm64=$(hash aivory-warden-aarch64-pc-windows-msvc.zip)
mac_arm=$(hash aivory-warden-aarch64-apple-darwin.tar.gz)
mac_x64=$(hash aivory-warden-x86_64-apple-darwin.tar.gz)
linux_x64=$(hash aivory-warden-x86_64-unknown-linux-gnu.tar.gz)
linux_arm64=$(hash aivory-warden-aarch64-unknown-linux-gnu.tar.gz)
date=$(date -u +%Y-%m-%d)

render() {
  sed -e "s/{{VERSION}}/$version/g" \
      -e "s/{{DATE}}/$date/g" \
      -e "s/{{SHA256_WINDOWS_X64}}/$win_x64/g" \
      -e "s/{{SHA256_WINDOWS_ARM64}}/$win_arm64/g" \
      -e "s/{{SHA256_MACOS_ARM64}}/$mac_arm/g" \
      -e "s/{{SHA256_MACOS_X64}}/$mac_x64/g" \
      -e "s/{{SHA256_LINUX_X64}}/$linux_x64/g" \
      -e "s/{{SHA256_LINUX_ARM64}}/$linux_arm64/g" \
      -e '/Template: packaging\/render-packages.sh/d' \
      "$1" > "$2"
}

# winget-pkgs layout: manifests/a/Aivory/Warden/<version>/
wdir="$out/winget/manifests/a/Aivory/Warden/$version"
mkdir -p "$wdir" "$out/homebrew/Formula" "$out/scoop/bucket"
for f in "$root"/packaging/winget/*.yaml; do
  render "$f" "$wdir/$(basename "$f")"
done
render "$root/packaging/homebrew/aivory-warden.rb" "$out/homebrew/Formula/aivory-warden.rb"
render "$root/packaging/scoop/aivory-warden.json" "$out/scoop/bucket/aivory-warden.json"

if grep -rq '{{' "$out"; then
  echo "render-packages: unfilled placeholder left in $out" >&2
  exit 1
fi
echo "render-packages: wrote $out"
