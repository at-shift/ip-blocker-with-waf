# WordPress.org Submission Notes

## Distribution Boundary

This is the `wordpress-org` branch of **atshift IP Blocker**, previously submitted as IP Blocker with WAF. The requested new slug and text domain are `atshift-ip-blocker`. This naming-only revision keeps the unreleased application version at 0.1.2; it does not add the GitHub main branch's newer SDN protocol or updater. The submission package is English-only and includes no PO/MO language pack, bundled translation template, external update checker, Update URI override, telemetry, remote block list or remote executable code. The separate GitHub distribution lives on `main`. These branches will be translated and integrated only after approval.

The package contains only `wordpress-plugin/`, under the installation directory `atshift-ip-blocker/`, with main file `atshift-ip-blocker.php`. Repository tests, QA results, configuration, databases and backups are not included. Runtime class names, `ipbw_*` settings/backup keys and `# BEGIN/END IP Blocker with WAF` markers remain for data and file compatibility; these are internal legacy identifiers, not the displayed plugin name or requested slug.

## Operation And Consent

This is not a WAF. It reads bounded local observations from existing supported WAFs after an administrator enables the relevant source. Reading logs and editing the server configuration are independent opt-ins, disabled initially. No automatic IP blocking occurs.

All views, changes and backup downloads require `manage_options` on a single-site installation. Write operations are POST-only and verify an action-specific WordPress nonce directly in each handler. Exact IP addresses and opt-in flags use strict validation rather than lossy normalization.

Editing is limited to the real site-home `.htaccess`, with a same-directory WordPress installation on Apache 2.4. It preserves unrelated bytes, ownership, group and permissions. A session-bound, expiring preview, file hash match, downloaded backup, client-IP acknowledgement and independent recovery acknowledgement are required. The latest three full backups remain privately in the local database.

## Narrowly Scoped Static-Analysis Exceptions

The source documents each exception at its exact call site; no Plugin Check category is excluded.

- `class-server-file.php` intentionally uses native local stream operations for exclusive creation (`x+b`, umask 0077), partial-write handling, flush/fsync, ownership/mode preservation and atomic same-directory rename. `WP_Filesystem::move()` permits copy-and-delete fallback, which cannot preserve this atomicity requirement. Cleanup deletes only the exact randomized temporary path created by the same transaction. There are no submitted filesystem paths or FTP operations.
- Provider-owned tables have no supported WordPress query API. Queries are prepared, read-only, explicitly administrator-triggered, and bounded to 10,000 recent rows and 200 IP/classification groups. Request payloads and raw JSON are not returned to PHP. Results are not persisted or cached as another IP log.
- The Semantic Deterrence guard must read live observation-window state. Lock expiry and release use atomic SQL compare-and-delete on the plugin's own option, followed by option-cache invalidation.
- Read-only navigation/filter parameters require administrator access but no nonce. They do not change blocking settings. Every write action separately verifies its nonce.
- The loopback health marker uses a random 256-bit token with a 90-second lifetime rather than a logged-in session nonce. It returns only a fixed marker, without configuration, logs, user data or a write operation. Redirects are disabled, TLS verification remains enabled, and no administrator cookies are sent.
- The exact configuration backup download is intentionally not HTML-escaped: it is an administrator-authorized, nonce-protected, no-cache `text/plain` attachment with `nosniff`, not HTML rendering.

## Compatibility And Limits

The initial provider schemas examined were CloudSecure WP Security 1.4.18 and Wordfence 9.0.2. Internal schemas are not compatibility contracts; missing/unsupported tables fail closed. Wordfence requires database JSON functions. Staging verification is required before production use, especially behind proxies/CDNs.

Self-checks do not guarantee recovery after process termination, hosting failure or a concurrent external edit. Keep independent hosting/SFTP access. Uninstall deliberately leaves server blocks and recovery data intact; remove unwanted managed blocks first. This behavior is documented in the plugin readme.

Plugin Check is an aid, not approval by the WordPress.org reviewers. The application has not been submitted by creating this package.
