=== atshift IP Blocker ===
Contributors: atshift
Tags: security, firewall, ip, access-control
Requires at least: 6.4
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Review existing WAF IP records and manually manage Apache server blocks with backups, previews and rollback checks.

== Description ==

This administrator-only tool reads bounded CloudSecure or Wordfence log records. Repeated candidates default to 30 records of the same classification from the same IP within a rolling ten-minute window. Different classifications are never combined; a candidate still needs manual review. Source reads and .htaccess editing are separate opt-ins, disabled by default. It is not a WAF, does not detect attacks, and never automatically blocks an IP based on its count.

Provider plugin pages: [CloudSecure WP Security](https://wordpress.org/plugins/cloudsecure-wp-security/) and [Wordfence](https://wordpress.org/plugins/wordfence/).

Apache 2.4, single-site WordPress and a same-directory site home are required for file editing. Select exact public IPs, review a preview, download the original file and confirm independent hosting/SFTP access before applying. The plugin preserves unrelated .htaccess bytes and manages only its own conditional-denial section.

Failed site checks attempt rollback but cannot guarantee recovery after process termination, hosting failures or concurrent changes. Verify compatibility on staging first. Deactivation/uninstall leaves server blocks and local recovery data intact. Existing manual deny rules are not managed by this plugin.

== Privacy ==

This WordPress.org distribution uses the standard WordPress.org update service. It contains no external update checker.

Source reads are administrator-triggered, limited to 10,000 retained rows and 200 IP/classification groups. Only IP, timestamp and classification fields are returned. Wordfence extracts a bounded category from valid JSON in the database; raw request data is not returned. Provider logs are never modified. There is no telemetry, Hub, geolocation service, remote block list or background collection.

Configured IPs, up to three full configuration backups, and expiring preview/readiness/probe/lock data remain in the local database. Applying a change sends random-token self-probes to this site's home URL, with no admin cookies, no redirects and normal TLS verification. Infrastructure access logs may contain those requests. Keep configuration backups private.

== Frequently Asked Questions ==

= Does this identify attackers or AI? =
No. A log entry or high count is not proof of an attack. An administrator must review each IP and its attribution.

= Does it support CDNs or proxies? =
It never independently trusts forwarding headers. Only use server editing when Apache's client-IP restoration and provider attribution have been correctly configured. Shared-service/proxy IP blocking can deny legitimate visitors.

= Can it run alongside Semantic Deterrence? =
Yes. With Semantic Deterrence 0.1.8 or later, responses and experiment assignment stay enabled during manual IP blocking. An opaque local measurement revision protects overlapping undecided windows: they are classified as rate_limited (indeterminate), never as deterrence success. No IP or WAF record is copied to SDN. Older SDN versions still refuse changes while responses or observation windows are active. Interrupted changes require explicit measurement recovery after a site health check.

== Changelog ==

= 1.0.0 =
* First stable WordPress.org release under the approved name atshift IP Blocker and slug atshift-ip-blocker.
* Include the latest SDN 0.1.8 coexistence and measurement recovery support from the GitHub pilot.
* Add bundled Japanese translations alongside the English interface using the approved text domain.
* Preserve existing ipbw settings, backups and managed .htaccess section markers.
* Use WordPress.org updates without a GitHub updater or Update URI override.
* Retain the reviewed submission nonce checks, strict input validation and documented atomic-file protections.


= 0.1.3 =
* Allow manual IP blocks alongside SDN experiments through the SDN 0.1.8 measurement API, without changing its mode or experiment assignment.
* Protect overlapping undecided observation windows from being classified as non-continuation successes; keep these results indeterminate in local and shared statistics.
* Require explicit, health-checked measurement recovery after an interrupted change. Preserve the legacy safety guard with older SDN versions.
* Show compatibility and recovery guidance before applying changes, and separate missing confirmations, expired previews and missing backup errors.

= 0.1.2 =
* Add GitHub Release notifications and plugin details through WordPress's normal update interface, only in the GitHub distribution.
* Validate stable release versions and exact repository assets, cache metadata, verify downloaded ZIPs against their named SHA-256 file, and reject missing or mismatched checksums.
* Keep the WordPress.org submission in a separate English-only branch without this updater. Retain Japanese translations in the GitHub package and register them on init.

= 0.1.1 =
* Add official WordPress.org introduction links for CloudSecure WP Security and Wordfence to the administrator connection settings and plugin documentation.
* Keep provider selection separate from external links, with mobile wrapping and safe new-tab attributes. Detection, grouping, blocking and backup behavior are unchanged.

= 0.1.0 =
* Initial pilot: administrator-only CloudSecure/Wordfence IP review, public-IP validation, protected addresses, bounded read-only queries, change previews, backup download, hash-checked replacement and guarded rollback.
