#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
output="${1:-$root/build}"
temp="$(mktemp -d)"
trap 'rm -rf "$temp"' EXIT
mkdir -p "$output" "$temp/atshift-ip-blocker"
output="$(cd "$output" && pwd)"
rsync -a --exclude='.DS_Store' --exclude='*~' "$root/wordpress-plugin/" "$temp/atshift-ip-blocker/"
cd "$temp"
zip -qr atshift-ip-blocker.zip atshift-ip-blocker
shasum -a 256 atshift-ip-blocker.zip > atshift-ip-blocker.zip.sha256
unzip -tq atshift-ip-blocker.zip
cp atshift-ip-blocker.zip atshift-ip-blocker.zip.sha256 "$output/"
printf 'Built %s/atshift-ip-blocker.zip\n' "$output"
