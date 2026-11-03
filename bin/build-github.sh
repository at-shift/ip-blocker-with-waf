#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
output="${1:-$root/build}"
mkdir -p "$output"
output="$(cd "$output" && pwd)"
temp="$(mktemp -d)"
trap 'rm -rf "$temp"' EXIT
mkdir -p "$temp/ip-blocker-with-waf/includes" "$temp/ip-blocker-with-waf/languages"
rsync -a --exclude='.DS_Store' --exclude='*~' "$root/wordpress-plugin/" "$temp/ip-blocker-with-waf/"
cp "$root/distribution/github/class-updater.php" "$temp/ip-blocker-with-waf/includes/"
cp "$root/distribution/github/languages/"* "$temp/ip-blocker-with-waf/languages/"
python3 - "$temp/ip-blocker-with-waf" <<'PY'
from pathlib import Path
import sys
root = Path(sys.argv[1])
entry = root / 'atshift-ip-blocker.php'
text = entry.read_text()
text = text.replace(' * Domain Path: /languages\n', ' * Domain Path: /languages\n * Update URI: https://github.com/at-shift/ip-blocker-with-waf\n')
text = text.replace("require_once __DIR__ . '/includes/class-admin.php';", "require_once __DIR__ . '/includes/class-admin.php';\nrequire_once __DIR__ . '/includes/class-updater.php';\nIP_Blocker_WAF_Updater::init();")
text = text.replace("\tload_plugin_textdomain( 'atshift-ip-blocker'", "\tload_plugin_textdomain( 'ip-blocker-with-waf', false, dirname( plugin_basename( __FILE__ ) ) . '/languages' );\n\tload_plugin_textdomain( 'atshift-ip-blocker'")
(root / 'ip-blocker-with-waf.php').write_text(text)
entry.unlink()
readme = root / 'readme.txt'
text = readme.read_text().replace('This WordPress.org distribution uses the standard WordPress.org update service. It contains no external update checker.', 'This GitHub compatibility distribution preserves the original ip-blocker-with-waf installation path and checksum-verified GitHub updater. Normal update checks contact GitHub and send no WAF records, site URL, administrator cookies or configuration backups. GitHub receives ordinary connection metadata such as the server IP. Metadata is cached for six hours, failures for fifteen minutes; automatic updates are not forced. The separate WordPress.org package contains no external updater. Do not activate both packages together.')
readme.write_text(text)
PY
cd "$temp"
zip -qr ip-blocker-with-waf.zip ip-blocker-with-waf
shasum -a 256 ip-blocker-with-waf.zip > ip-blocker-with-waf.zip.sha256
unzip -tq ip-blocker-with-waf.zip
cp ip-blocker-with-waf.zip ip-blocker-with-waf.zip.sha256 "$output/"
printf 'Built %s/ip-blocker-with-waf.zip\n' "$output"
