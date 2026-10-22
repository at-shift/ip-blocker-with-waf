#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
output="${1:-$root/build}"
temp="$(mktemp -d)"
trap 'rm -rf "$temp"' EXIT
mkdir -p "$output" "$temp/ip-blocker-with-waf"
rsync -a --exclude='.DS_Store' "$root/wordpress-plugin/" "$temp/ip-blocker-with-waf/"
cd "$temp"
zip -qr ip-blocker-with-waf.zip ip-blocker-with-waf
shasum -a 256 ip-blocker-with-waf.zip > ip-blocker-with-waf.zip.sha256
unzip -tq ip-blocker-with-waf.zip
cp ip-blocker-with-waf.zip ip-blocker-with-waf.zip.sha256 "$output/"
printf 'Built %s/ip-blocker-with-waf.zip\n' "$output"
