# WordPress.org release 1.0.0

Published on 2026-10-28 (Asia/Tokyo) to `atshift-ip-blocker`.

- SVN revision: **3770325**.
- The reviewed, English-only 0.1.2 archive is retained in `tags/0.1.2`.
- `trunk` and `tags/1.0.0` contain the latest SDN coexistence support and English/Japanese interfaces. Both tags and trunk were committed together so the first advertised stable release is 1.0.0.
- WordPress.org API reports version 1.0.0 and the official download URL.
- Official ZIP was independently downloaded, passed archive integrity checks, and matched every file in the validated local package.
- Official ZIP SHA-256: `0576fede90df360141bb9b26fabd34bc3f5646313739d7a2c4ffafbfb7d3b7d4`.
- Local ZIP SHA-256: `3d7f0d7ec6c16a3d9925ac4a8fb01736d57b27efb5c2476d110cf7e671be35fb`. ZIP metadata differs from WordPress.org's archive; extracted contents are identical.

Validation used isolated WordPress 7.1, PHP 8.3.36 and MySQL 8.4.9:

- Plugin Check 2.1.0, with runtime support: no findings.
- 84 rule/transaction/privacy/permission checks, 14 identity checks, 15 SDN measurement checks, 16 admin-flow checks.
- 16 real WordPress metadata, locale, rendered view, saved setting and access checks.
- 117 translated Japanese catalog entries; gettext syntax and format checks passed.
- PHP lint and clean diff checks passed.

The WordPress.org package contains no GitHub updater. The older GitHub distribution on `main` is separate and must not be active alongside it. Existing `ipbw_*` options, backups and managed `.htaccess` markers are retained. No production site's configuration or plugin installation was changed by this release.

Public page: https://wordpress.org/plugins/atshift-ip-blocker/

Official ZIP: https://downloads.wordpress.org/plugin/atshift-ip-blocker.1.0.0.zip
