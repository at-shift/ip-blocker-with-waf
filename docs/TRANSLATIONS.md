# Interface translations

Version 1.0.1 includes English source strings and 14 bundled gettext catalogs:

| Locale | Language |
| --- | --- |
| ja | Japanese |
| es_ES | Spanish |
| de_DE | German |
| fr_FR | French |
| pt_BR | Brazilian Portuguese |
| it_IT | Italian |
| ru_RU | Russian |
| nl_NL | Dutch |
| zh_CN | Simplified Chinese |
| pl_PL | Polish |
| tr_TR | Turkish |
| id_ID | Indonesian |
| zh_TW | Traditional Chinese (Taiwan) |
| ko_KR | Korean |

The interface follows the current WordPress user's locale, including when it differs from the site's default locale. WordPress.org language packs can take priority over the bundled fallback.

## Meaning that must be preserved

- A WAF record or a high record count is not proof of an attack or of identical payloads.
- This tool does not detect attacks or block automatically. Source reading and manual server editing are separate opt-ins.
- Verify exact client-IP attribution, including CDN/proxy and shared-service addresses, before applying a block.
- A downloaded backup and independent hosting/SFTP recovery access are required. Self-checks do not guarantee recovery or prove that the selected remote IP was blocked.
- Deactivation/uninstall leaves server blocks and recovery data intact.
- Failed, unknown and interrupted states must not be described as successful changes. SDN interference is indeterminate, not deterrence success.
- Provider logs are local and unchanged. No raw IP log, attack payload or configuration backup is shared externally by this plugin.

Translate full messages, including limitations. Preserve brand names, file names, identifiers, printf placeholders and numeric limits. Do not translate `.htaccess`, `REMOTE_ADDR`, `SERVER_ADDR`, `SDN`, `blocked:waf` or `SFTP` into different identifiers.

## Validation

Translations are agent-authored and reviewed without Google Translate or another external translation service. Automated checks complement the meaning review; they do not constitute native-speaker certification.

For 1.0.1, each of the 13 added catalogs received a second, read-only review by a different agent. One ambiguity in the Italian permissions guidance was corrected to state that execution is forbidden for all users, while write access is forbidden for group/other users. No other material translation issues were found in that review.

Run `python3 tests/translations.py` with GNU gettext installed. It checks the exact locale set, all 117 active source entries, headers, nonempty translations, printf placeholders, technical identifiers and freshly compiled MO equality. The isolated WordPress release fixture checks every compiled translation through WordPress's locale switcher, renders all three views in every locale, and exercises settings/permission checks.

To regenerate source messages, run `wp i18n make-pot wordpress-plugin wordpress-plugin/languages/atshift-ip-blocker.pot --domain=atshift-ip-blocker --slug=atshift-ip-blocker --exclude=languages`. Update catalogs without accepting fuzzy translations, compile each PO with `msgfmt --check --check-format`, and rerun validation before packaging.

Corrections from native speakers are welcome, especially where security guidance could be misinterpreted. Include the locale and complete English source string when reporting an issue.
