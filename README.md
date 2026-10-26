# IP Blocker with WAF

**GitHub distribution (`main`).** The English-only [WordPress.org submission branch](https://github.com/at-shift/ip-blocker-with-waf/tree/wordpress-org) is maintained separately, without bundled languages or a GitHub updater. Do not merge the submission branch until approval; translation and integration follow approval.

**A local, administrator-operated WordPress desk for reviewing WAF IP records and manually managing Apache IP blocks.**

Existing WAFs may record hundreds of repeat requests from one address. This plugin reads a bounded slice of those existing records, lets an administrator review the addresses, and prepares a reversible server configuration change. It does not detect attacks, replace the WAF, or automatically block an IP based on a count.

## Current Scope

- WordPress 6.4+, PHP 7.4+; Apache 2.4, single-site WordPress installed in the site-home directory.
- [CloudSecure WP Security](https://wordpress.org/plugins/cloudsecure-wp-security/): retained detection counts per IP. A detection is not necessarily a blocked request.
- [Wordfence](https://wordpress.org/plugins/wordfence/): retained `blocked:waf` records with a valid category from `wfHits`. The database extracts only a bounded category from JSON; raw action data is not returned. MySQL/MariaDB JSON functions are required; unsupported schemas fail closed. Generic IP blocks and learning-mode records are not used as same-classification evidence.
- Repeat candidates default to **30 records from the same IP and classification within a rolling ten-minute window** during the selected period. Choose 20/30/50/100 records and 5/10/30 minutes. Different classifications never combine to cross the threshold; single records are not selectable candidates. Manual IP-list entry remains an explicit administrator override for independently verified addresses.
- Administrator-only screens and actions (`manage_options`), including direct URLs and backup downloads.
- Exact public IPv4/IPv6 only, at most 50 managed IPs. No hostnames, ranges, masked IPs or private/reserved addresses.
- Protects the current `REMOTE_ADDR`, `SERVER_ADDR`, and explicitly configured IPs from selection. Never trusts forwarding headers on its own.
- WAF reads and server editing are separate opt-ins, both disabled initially.
- English source strings and Japanese admin translations. Public repository documentation is in English.

The tested provider sources are CloudSecure 1.4.18 and Wordfence 9.0.2. Their internal schemas are not public compatibility contracts. SiteGuard login histories are not general WAF logs; BBQ has no built-in historical IP log; NinjaFirewall may mask IPs. These adapters are deliberately not included in this first version.

## Manual Apply Workflow

1. Explicitly enable the required log source and server editing in **Connections & safety**. Confirm that the site's IP attribution is correct, especially behind a CDN/proxy.
2. Review the source-specific records, select IPs, or edit the existing managed IP list under **Server blocks**. An empty replacement list removes only this plugin's section.
3. Generate a preview. The preview expires after ten minutes and is bound to the current user's session context and current file hash.
4. Download the current `.htaccess` backup. Confirm independent hosting/SFTP recovery access and that the selected IPs are client addresses, not shared-service or proxy addresses.
5. Apply. The plugin verifies the original file hash again, runs a baseline loopback probe, saves a private database backup, replaces the file via a same-directory temporary file and rename, and repeats the probe.
6. A failed post-change check attempts to restore the exact previous file. It refuses to overwrite a concurrent external change during rollback; manual recovery may then be required.

The generated section uses Apache 2.4 `<If "-R 'address'">` with `Require all denied`. It adds a conditional denial without introducing a blanket `Require all granted` or changing `Order`/`Allow`/`Deny` policy. It does not edit existing manually added deny rules. See [Apache expression documentation](https://httpd.apache.org/docs/2.4/expr.html) and [access-control documentation](https://httpd.apache.org/docs/2.4/howto/access.html). Legacy `Deny from` is intentionally not generated because Apache deprecates those directives.

Only one strictly validated managed section at the beginning of `.htaccess` is editable. Other bytes, including WordPress rules, are preserved. File ownership, group and mode are retained; inability to preserve them aborts the change. Ambiguous, duplicate, moved, or externally modified sections are rejected. Symbolic links, files above 128 KiB, executable/group-writable/world-writable settings files, and unsupported environments are rejected.

### Recovery Is Not Guaranteed

Self-checks prove only that a probe reached this plugin, not that a selected remote address was blocked or every site route still works. Cached, proxied, authenticated, redirected, Basic-Auth-protected or loopback-restricted deployments may fail preflight and remain uneditable.

A PHP process can terminate after replacement but before verification or rollback. Hosting failures or concurrent changes can also prevent recovery. **Keep the downloaded original file and independent hosting/SFTP access.** Do not edit `.htaccess` simultaneously through another tool. Backups are not stored as public files, but the full configuration is retained privately in the local WordPress database (latest three images).

Deactivation or uninstall does **not** remove server blocks or recovery data. Remove the managed section before uninstalling if the blocks are no longer required. To clean up after server recovery, remove the plugin's `ipbw_settings`, `ipbw_backups`, `ipbw_write_lock` options and expired `ipbw_*` transients through a trusted database administration tool. Never remove another plugin's records.

## Privacy And Load

- No telemetry, Hub, geolocation service, remote block list, automatic WAF installation or background request collection.
- No observed WAF IP, site URL, attack payload or configuration backup is sent to GitHub or a third-party service. Publishing this repository shares source code only.
- Only IP, timestamp and detection-classification fields are returned to the plugin. Wordfence categories are extracted from its JSON in the database with a length guard; full JSON, URLs, matched strings, cookies, usernames, bodies and User-Agent values are not returned.
- The log screen reads at most the latest 10,000 provider rows and returns at most 200 IP/classification groups, sorted by peak-window count. Counts are local reference observations, not proof of an attack or identical payloads. Peak windows may be historical within the selected period; review last-seen/peak timestamps before acting. High-volume or expired logs can truncate the requested period. No automatic refresh, per-request hooks, or scheduled scans are added.
- Source rows are not copied into another event table. Configured/protected IPs, up to three full configuration backups, preview plans, and short-lived readiness/probe/lock data remain locally. Expired WordPress transients may be physically removed later by WordPress cleanup.
- Applying a change performs two unauthenticated HTTP self-probes to the configured site home, with random short-lived tokens, no admin cookies, redirects disabled, and normal TLS verification. A token reveals only a fixed health marker. Hosting/CDN access logs can contain that URL and the connecting server IP.
- Public admin URLs do not contain IP selections. Pages containing IPs request no-cache headers. Trusted WordPress administrators and database operators can access locally retained configuration data.

## Semantic Deterrence Compatibility

This project is separate from Semantic Deterrence and has no aggregate-sharing integration. Server blocking prevents later requests from reaching WordPress; absence of follow-up is therefore not evidence of a semantic warning's effect.

With Semantic Deterrence **0.1.8 or later**, manual server blocks can coexist with its deterrence/experiment responses. Its mode, response selection and experiment assignment do not change. Before attempting a file change, SDN records an opaque local measurement revision and conservatively marks overlapping undecided response windows as `rate_limited` (indeterminate), not `observed_ceased`. This affects all still-open undecided windows, not only the selected IP: no IP-to-series lookup or additional raw-IP retention is introduced. Already observed continuation and completed results are preserved. Unfinalized older revisions are conservatively censored too; late requests and failed post-insert updates cannot become false non-continuation successes.

The revision contains only a random token, start time and pending flag; it is never exported. Events persist only the revision token locally, and export explicitly excludes it. A new API is required on **both plugins**. With older SDN versions, the original refusal remains while responses or windows are active, with an update message shown before applying. Unknown state fails closed.

Ordinary failed/rolled-back attempts also censor overlapping windows conservatively. If a process stops or measurement completion fails, SDN keeps counting new responses as indeterminate. Review the current managed list and independent recovery access, then use **Resume SDN measurement** in Server blocks. This runs a site health check and closes the pending measurement change without rewriting `.htaccess`. Never automatically clear this state on a timer. Other external blocking tools and manual hosting edits remain outside this integration; their interference is not detectable by this API.

## Repository And Development

### GitHub Updates In WordPress

This distribution uses WordPress's normal plugin-update interface to check the latest stable public GitHub Release. It requires the exact installable `ip-blocker-with-waf.zip` asset and its `.sha256` companion from this repository. Downloads are streamed with TLS verification and rejected if SHA-256 verification fails. Checksums detect mismatches; they are not an independent signature or protection against a compromised publisher account.

Successful metadata is cached for six hours, failures for fifteen minutes. Normal update checks and the plugin-information modal contact GitHub; downloads occur through WordPress's upgrade flow. Requests use a plugin/version-only User-Agent, without site URLs, administrator cookies or WAF records. GitHub/CDN servers receive ordinary connection metadata such as the connecting server IP. The updater does not force automatic updates or modify other plugins' update results.

**Versions 0.1.1 and earlier have no GitHub updater. Install 0.1.2 once manually to enable future WordPress update notifications.** The `wordpress-org` submission package does not include this updater or an external Update URI.

`wordpress-plugin/` is the installable source. `tests/` contains inert, isolated regression fixtures. No third-party WAF code is redistributed.

```sh
php tests/run.php
php tests/updater.php
find wordpress-plugin tests -name '*.php' -print0 | xargs -0 -n1 php -l
msgfmt --check --check-format -o /dev/null wordpress-plugin/languages/ip-blocker-with-waf-ja.po
bash bin/build.sh /tmp/ip-blocker-with-waf-package
```

The ZIP root is `ip-blocker-with-waf/`. Do not install a GitHub source archive as the plugin ZIP without repackaging `wordpress-plugin/`.

Initial verification uses an isolated filesystem and mocked WordPress/provider data, plus an isolated Apache configuration and rendered desktop/mobile fixture. It does not prove compatibility with every hosting environment, provider configuration, reverse proxy, or live MySQL deployment. Test on a staging copy with independent recovery access before production use.

## Contributing And Security

Pull requests are welcome for bounded read-only provider adapters, compatibility fixtures, translations, accessibility and recovery hardening. Do not submit real IP logs, tokens, `.htaccess` backups, database credentials or live attack payloads. Use documentation/test addresses or inert synthetic fixtures.

Report suspected security issues privately to the repository owner rather than opening a public exploit issue. This project is GPL-2.0-or-later and is an early pilot, not a guarantee of prevention or availability.
